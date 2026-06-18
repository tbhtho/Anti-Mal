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
  int count = 0;              // how many crashes matched this signature
};

struct CrashSummary {
  int totalCrashes = 0;
  std::vector<CrashSignature> signatures; // distinct, sorted by count desc
};

// Map a hex NTSTATUS exception code (lower/upper case, with or without "0x") to a
// short human name. Returns "" for codes we don't have a label for.
std::string ExceptionCodeName(const std::string &hexCode);

// Aggregate `process.crash` events into distinct fault signatures. Pure +
// deterministic (ties broken by signature text). Non-crash events are ignored.
CrashSummary SummarizeCrashes(const std::vector<EventRecord> &events);

} // namespace antimal
