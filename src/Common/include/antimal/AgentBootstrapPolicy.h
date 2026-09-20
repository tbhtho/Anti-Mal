#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace antimal {
// Recognize only AntiMal's own seeded Run fallback, never arbitrary startup work.
inline bool IsSeededAgentAutorun(uint32_t type,
                                const std::vector<uint8_t> &bytes) {
  if (type != 1 || bytes.size() < 2 || bytes.size() > 4096 || bytes.size() % 2)
    return false;
  std::string command;
  bool terminated = false;
  for (size_t i = 0; i < bytes.size(); i += 2) {
    const unsigned c = bytes[i] | (static_cast<unsigned>(bytes[i + 1]) << 8);
    if (terminated) {
      if (c != 0) return false;
      continue;
    }
    if (c == 0) { terminated = true; continue; }
    if (c > 127) return false;
    command.push_back(static_cast<char>(c >= 'A' && c <= 'Z' ? c + 32 : c));
  }
  return terminated &&
      (command == "c:\\antimal\\antimal.guestagent.exe --service" ||
       command == "\"c:\\antimal\\antimal.guestagent.exe\" --service");
}
} // namespace antimal
