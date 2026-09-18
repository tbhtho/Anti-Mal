#include "antimal/Crypto.h"

#include "antimal/FileUtil.h"

#include <Windows.h>
#include <bcrypt.h>
#include <dpapi.h>

#include <iomanip>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace antimal {
namespace {

class BCryptAlg {
public:
  explicit BCryptAlg(const wchar_t *algorithm) {
    const NTSTATUS status = BCryptOpenAlgorithmProvider(&handle_, algorithm, nullptr, 0);
    if (status < 0) {
      throw std::runtime_error("BCryptOpenAlgorithmProvider failed");
    }
  }

  ~BCryptAlg() {
    if (handle_) {
      BCryptCloseAlgorithmProvider(handle_, 0);
    }
  }

  BCRYPT_ALG_HANDLE get() const { return handle_; }

private:
  BCRYPT_ALG_HANDLE handle_ = nullptr;
};

std::string Hex(const std::vector<uint8_t> &bytes) {
  std::ostringstream out;
  for (uint8_t b : bytes) {
    out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
  }
  return out.str();
}

// Streaming BCrypt file hash: reads the file in bounded chunks so hashing a
// multi-GB installer does not require the whole file in host memory (the old
// ReadAllBytes-based path needed 2.34 GB RAM for a 2.34 GB package). Same
// digest as the one-shot path; throws on open/read/hash failure like before.
std::string HashFileHex(const wchar_t *algorithm,
                        const std::filesystem::path &path) {
  BCryptAlg alg(algorithm);
  DWORD hashLength = 0;
  DWORD cbData = 0;
  if (BCryptGetProperty(alg.get(), BCRYPT_HASH_LENGTH,
                        reinterpret_cast<PUCHAR>(&hashLength), sizeof(hashLength),
                        &cbData, 0) < 0) {
    throw std::runtime_error("BCryptGetProperty(BCRYPT_HASH_LENGTH) failed");
  }
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    throw std::runtime_error("unable to open file for hashing: " +
                             PathToUtf8(path));
  }
  BCRYPT_HASH_HANDLE hash = nullptr;
  if (BCryptCreateHash(alg.get(), &hash, nullptr, 0, nullptr, 0, 0) < 0) {
    throw std::runtime_error("BCryptCreateHash failed");
  }
  std::vector<char> buffer(1u << 20); // 1 MiB
  while (in) {
    in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    const std::streamsize got = in.gcount();
    if (got <= 0) {
      break;
    }
    if (BCryptHashData(hash, reinterpret_cast<PUCHAR>(buffer.data()),
                       static_cast<ULONG>(got), 0) < 0) {
      BCryptDestroyHash(hash);
      throw std::runtime_error("BCryptHashData failed");
    }
  }
  std::vector<uint8_t> digest(hashLength);
  const bool ok = BCryptFinishHash(hash, digest.data(), hashLength, 0) >= 0;
  BCryptDestroyHash(hash);
  if (!ok) {
    throw std::runtime_error("BCryptFinishHash failed");
  }
  return Hex(digest);
}

// Shared one-shot BCrypt hash: open the named algorithm, hash all of `data`,
// return the lowercase-hex digest. Used by both Sha256Hex and Md5Hex so the
// error handling / digest-length plumbing lives in exactly one place.
std::string HashHex(const wchar_t *algorithm, const std::vector<uint8_t> &data) {
  BCryptAlg alg(algorithm);

  DWORD hashLength = 0;
  DWORD cbData = 0;
  if (BCryptGetProperty(alg.get(), BCRYPT_HASH_LENGTH,
                        reinterpret_cast<PUCHAR>(&hashLength), sizeof(hashLength),
                        &cbData, 0) < 0) {
    throw std::runtime_error("BCryptGetProperty(BCRYPT_HASH_LENGTH) failed");
  }

  BCRYPT_HASH_HANDLE hash = nullptr;
  if (BCryptCreateHash(alg.get(), &hash, nullptr, 0, nullptr, 0, 0) < 0) {
    throw std::runtime_error("BCryptCreateHash failed");
  }

  if (!data.empty() &&
      BCryptHashData(hash, const_cast<PUCHAR>(data.data()),
                     static_cast<ULONG>(data.size()), 0) < 0) {
    BCryptDestroyHash(hash);
    throw std::runtime_error("BCryptHashData failed");
  }

  std::vector<uint8_t> digest(hashLength);
  if (BCryptFinishHash(hash, digest.data(), hashLength, 0) < 0) {
    BCryptDestroyHash(hash);
    throw std::runtime_error("BCryptFinishHash failed");
  }
  BCryptDestroyHash(hash);
  return Hex(digest);
}

} // namespace

std::string Sha256Hex(const std::vector<uint8_t> &data) {
  return HashHex(BCRYPT_SHA256_ALGORITHM, data);
}

std::string Sha256File(const std::filesystem::path &path) {
  return HashFileHex(BCRYPT_SHA256_ALGORITHM, path);
}

std::string Md5Hex(const std::vector<uint8_t> &data) {
  return HashHex(BCRYPT_MD5_ALGORITHM, data);
}

std::string Md5File(const std::filesystem::path &path) {
  return HashFileHex(BCRYPT_MD5_ALGORITHM, path);
}

std::string Sha1Hex(const std::vector<uint8_t> &data) {
  return HashHex(BCRYPT_SHA1_ALGORITHM, data);
}

std::string Sha1File(const std::filesystem::path &path) {
  return HashFileHex(BCRYPT_SHA1_ALGORITHM, path);
}

std::optional<std::vector<uint8_t>> DpapiUnprotect(const std::vector<uint8_t> &ciphertext) {
  if (ciphertext.empty()) {
    return std::nullopt;
  }

  DATA_BLOB input{};
  input.pbData = const_cast<BYTE *>(ciphertext.data());
  input.cbData = static_cast<DWORD>(ciphertext.size());

  DATA_BLOB output{};
  if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, 0, &output)) {
    return std::nullopt;
  }

  std::vector<uint8_t> plain(output.pbData, output.pbData + output.cbData);
  LocalFree(output.pbData);
  return plain;
}

std::optional<std::vector<uint8_t>> AesGcmDecrypt(const std::vector<uint8_t> &key,
                                                  const std::vector<uint8_t> &nonce,
                                                  const std::vector<uint8_t> &ciphertext,
                                                  const std::vector<uint8_t> &tag) {
  if (key.empty() || nonce.empty() || tag.empty()) {
    return std::nullopt;
  }

  try {
    BCryptAlg alg(BCRYPT_AES_ALGORITHM);
    if (BCryptSetProperty(alg.get(), BCRYPT_CHAINING_MODE,
                          reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(BCRYPT_CHAIN_MODE_GCM)),
                          static_cast<ULONG>((wcslen(BCRYPT_CHAIN_MODE_GCM) + 1) *
                                             sizeof(wchar_t)),
                          0) < 0) {
      return std::nullopt;
    }

    BCRYPT_KEY_HANDLE hKey = nullptr;
    if (BCryptGenerateSymmetricKey(alg.get(), &hKey, nullptr, 0,
                                   const_cast<PUCHAR>(key.data()),
                                   static_cast<ULONG>(key.size()), 0) < 0) {
      return std::nullopt;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = const_cast<PUCHAR>(nonce.data());
    authInfo.cbNonce = static_cast<ULONG>(nonce.size());
    authInfo.pbTag = const_cast<PUCHAR>(tag.data());
    authInfo.cbTag = static_cast<ULONG>(tag.size());

    std::vector<uint8_t> plain(ciphertext.size());
    ULONG plainSize = 0;
    const NTSTATUS status = BCryptDecrypt(
        hKey, const_cast<PUCHAR>(ciphertext.data()), static_cast<ULONG>(ciphertext.size()),
        &authInfo, nullptr, 0, plain.data(), static_cast<ULONG>(plain.size()), &plainSize, 0);

    BCryptDestroyKey(hKey);
    if (status < 0) {
      return std::nullopt;
    }
    plain.resize(plainSize);
    return plain;
  } catch (...) {
    return std::nullopt;
  }
}

} // namespace antimal
