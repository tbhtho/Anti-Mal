#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace antimal {

std::string Sha256Hex(const std::vector<uint8_t> &data);
std::string Sha256File(const std::filesystem::path &path);
std::optional<std::vector<uint8_t>> DpapiUnprotect(const std::vector<uint8_t> &ciphertext);
std::optional<std::vector<uint8_t>> AesGcmDecrypt(const std::vector<uint8_t> &key,
                                                  const std::vector<uint8_t> &nonce,
                                                  const std::vector<uint8_t> &ciphertext,
                                                  const std::vector<uint8_t> &tag);

} // namespace antimal
