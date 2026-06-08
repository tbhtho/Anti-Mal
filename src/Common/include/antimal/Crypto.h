#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace antimal {

std::string Sha256Hex(const std::vector<uint8_t> &data);
std::string Sha256File(const std::filesystem::path &path);
// SHA-1 is collision-broken but is still a primary cross-reference key in AV /
// threat-intel feeds (VT, MalwareBazaar) -- exposed for IDENTIFICATION ONLY.
std::string Sha1Hex(const std::vector<uint8_t> &data);
std::string Sha1File(const std::filesystem::path &path);
// MD5 is cryptographically broken but remains the lingua franca of malware
// triage (imphash, AV feeds, MalwareBazaar/VT cross-referencing) -- exposed for
// IDENTIFICATION ONLY, never for a security decision.
std::string Md5Hex(const std::vector<uint8_t> &data);
std::string Md5File(const std::filesystem::path &path);
std::optional<std::vector<uint8_t>> DpapiUnprotect(const std::vector<uint8_t> &ciphertext);
std::optional<std::vector<uint8_t>> AesGcmDecrypt(const std::vector<uint8_t> &key,
                                                  const std::vector<uint8_t> &nonce,
                                                  const std::vector<uint8_t> &ciphertext,
                                                  const std::vector<uint8_t> &tag);

} // namespace antimal
