#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace antimal {

struct PeInfo {
  bool isPe = false;
  uint16_t machine = 0;
  uint16_t numberOfSections = 0;
  uint16_t subsystem = 0;
  std::vector<std::string> imports;
};

PeInfo ParsePe(const std::vector<uint8_t> &data);
PeInfo ParsePeFile(const std::filesystem::path &path);
bool HasAuthenticodeSignature(const std::filesystem::path &path);

} // namespace antimal
