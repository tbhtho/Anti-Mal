#include "antimal/ShellcodeDetector.h"

namespace antimal {

ShellcodeIndicators DetectShellcode(const std::vector<uint8_t> &data) {
  ShellcodeIndicators ind;
  const size_t n = data.size();
  const uint8_t *p = data.data();

  for (size_t i = 0; i < n; ++i) {
    // GetPC: E8 00 00 00 00 (call $+5) immediately followed by a pop r32/r64
    // (0x58-0x5F). 6 anchored bytes -> effectively zero false positives.
    if (i + 5 < n && p[i] == 0xE8 && p[i + 1] == 0x00 && p[i + 2] == 0x00 &&
        p[i + 3] == 0x00 && p[i + 4] == 0x00 && p[i + 5] >= 0x58 &&
        p[i + 5] <= 0x5F) {
      ind.getPcCallPop = true;
      ++ind.getPcCount;
    }

    // x86 PEB walk: mov eax, fs:[0x30]  ->  64 A1 30 00 00 00
    if (i + 5 < n && p[i] == 0x64 && p[i + 1] == 0xA1 && p[i + 2] == 0x30 &&
        p[i + 3] == 0x00 && p[i + 4] == 0x00 && p[i + 5] == 0x00) {
      ind.pebWalk = true;
      ++ind.pebWalkCount;
    }
    // x86 PEB walk (ModRM form): mov e?x, fs:[0x30] -> 64 8B ?? 30 ...
    // Match the common `64 8B 1D 30 00 00 00` (mov ebx, fs:[0x30]) family by the
    // fs prefix + mov r32,disp32 opcode + the 0x30 displacement.
    if (i + 6 < n && p[i] == 0x64 && p[i + 1] == 0x8B &&
        (p[i + 2] & 0xC7) == 0x05 && p[i + 3] == 0x30 && p[i + 4] == 0x00 &&
        p[i + 5] == 0x00 && p[i + 6] == 0x00) {
      ind.pebWalk = true;
      ++ind.pebWalkCount;
    }

    // x64 PEB walk: mov rax, gs:[0x60] -> 65 48 8B 04 25 60 00 00 00
    if (i + 8 < n && p[i] == 0x65 && p[i + 1] == 0x48 && p[i + 2] == 0x8B &&
        p[i + 3] == 0x04 && p[i + 4] == 0x25 && p[i + 5] == 0x60 &&
        p[i + 6] == 0x00 && p[i + 7] == 0x00 && p[i + 8] == 0x00) {
      ind.pebWalk = true;
      ++ind.pebWalkCount;
    }
  }

  if (ind.getPcCallPop) {
    ind.reasons.push_back("GetPC call/pop stub (E8 00000000 + pop) x" +
                          std::to_string(ind.getPcCount));
  }
  if (ind.pebWalk) {
    ind.reasons.push_back("PEB access for kernel32 base (fs:[0x30]/gs:[0x60]) x" +
                          std::to_string(ind.pebWalkCount));
  }
  return ind;
}

} // namespace antimal
