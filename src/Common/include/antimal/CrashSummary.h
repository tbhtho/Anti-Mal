#pragma once

// Crash-signature summary.
//
// A detonation (or a sandbox boot) can produce many `process.crash` telemetry
// events; raw, they're just spam. This collapses them into distinct fault
// SIGNATURES -- (image, exception code, faulting module + version + offset) with
// a count and a human-readable exception name -- so an analyst sees "Explorer
// crashed 51x with c0000409 (__fastfail) in ucrtbase.dll" instead of 51 lines.
// Useful for both the known Win11 modern-shell wall AND a detonated sample that
// crashes (a real behavioral signal). Pure: a function of the events only.

#include "antimal/Types.h"

#include <string>
#include <vector>

namespace antimal {

struct CrashSignature {
  std::string image;          // crashing process image (e.g. "Explorer.EXE")
  std::string exceptionCode;  // hex NTSTATUS, e.g. "c0000409"
  std::string exceptionName;  // human name, e.g. "__fastfail / stack-buffer-overrun"
  std::string module;         // faulting module (e.g. "ucrtbase.dll")
  std::string moduleVersion;  // module version when captured
  std::string offset;         // fault offset within the module
  // The __fastfail SUBCODE (RCX at the `int 29h`, == ExceptionInformation[0] of
  // a 0xC0000409). This is the single most diagnostic field for the Win11
  // modern-shell crash-loop: it says WHY the fast-fail fired (e.g. 7 =
  // FATAL_APP_EXIT == unhandled C++/WinRT exception -> abort/terminate, vs 2 =
  // stack-cookie, vs 10/11 = CFG). -1 when the capture didn't include it.
  long fastFailSubcode = -1;
  std::string fastFailName;   // decoded subcode name, e.g. "FATAL_APP_EXIT"; "" if none
  int count = 0;              // how many crashes matched this signature
};

struct CrashSummary {
  int totalCrashes = 0;
  std::vector<CrashSignature> signatures; // distinct, sorted by count desc
};

// Map a hex NTSTATUS exception code (lower/upper case, with or without "0x") to a
// short human name. Returns "" for codes we don't have a label for.
std::string ExceptionCodeName(const std::string &hexCode);

// Map a Windows __fastfail SUBCODE (the FAST_FAIL_* enum from winnt.h, i.e. the
// value in RCX at the `int 29h` / ExceptionInformation[0] of a 0xC0000409) to its
// symbolic name -- WITHOUT the "FAST_FAIL_" prefix (e.g. 7 -> "FATAL_APP_EXIT",
// 2 -> "STACK_COOKIE_CHECK_FAILURE"). Returns "" for codes outside the known
// table. This is the decode half of the shell-wall diagnostic: once a crash event
// carries the subcode, this names the precise fast-fail reason.
std::string FastFailName(long subcode);

// Aggregate `process.crash` events into distinct fault signatures. Pure +
// deterministic (ties broken by signature text). Non-crash events are ignored.
CrashSummary SummarizeCrashes(const std::vector<EventRecord> &events);

} // namespace antimal
