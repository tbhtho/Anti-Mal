#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace antimal {

// Heuristic detection of x86/x64 shellcode (position-independent code) by its
// most distinctive, low-false-positive byte signatures. Shellcode rides in the
// places a normal PE parse never looks — maldoc/script payloads, RTF/OLE blobs,
// downloaded stage buffers, and PE overlays — so this runs on raw bytes.
//
// The two anchored tells:
//  - GetPC via call/pop: `E8 00 00 00 00` (call $+5) immediately followed by a
//    pop r32 (58-5F). The canonical way PIC learns its own address; ~never
//    appears in benign data (6 highly-specific bytes).
//  - PEB walk: `mov eax, fs:[0x30]` (x86) / `mov rax, gs:[0x60]` (x64) — the
//    classic kernel32-base discovery prologue. Strong, but it CAN appear in
//    legitimately compiled PE code, so the caller gates this to non-PE / overlay
//    contexts (see Scanner).
struct ShellcodeIndicators {
  bool getPcCallPop = false; // E8 00 00 00 00 5x  (very low FP)
  bool pebWalk = false;      // fs:[0x30] / gs:[0x60]
  int getPcCount = 0;
  int pebWalkCount = 0;
  std::vector<std::string> reasons;
  bool Any() const { return getPcCallPop || pebWalk; }
};

ShellcodeIndicators DetectShellcode(const std::vector<uint8_t> &data);

} // namespace antimal
