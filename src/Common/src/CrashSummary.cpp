#include "antimal/CrashSummary.h"

#include <algorithm>
#include <cctype>
#include <map>

namespace antimal {

namespace {

std::string Lower(std::string s) {
  for (char &c : s) c = static_cast<char>(std::tolower((unsigned char)c));
  return s;
}

// Normalize a hex status to bare lowercase hex (strip "0x", leading zeros kept
// as-is so well-known full forms like "c0000409" match).
std::string NormCode(const std::string &in) {
  std::string s = Lower(in);
  if (s.rfind("0x", 0) == 0) s = s.substr(2);
  return s;
}

std::string DetailOr(const EventRecord &e, const std::string &key) {
  const auto it = e.details.find(key);
  return it == e.details.end() ? std::string() : it->second;
}

} // namespace

std::string ExceptionCodeName(const std::string &hexCode) {
  // The common Windows NTSTATUS / exception codes seen in crash telemetry.
  static const std::map<std::string, std::string> kNames = {
      {"c0000005", "access violation"},
      {"c0000409", "__fastfail / stack-buffer-overrun"},
      {"c0000374", "heap corruption"},
      {"c000041d", "fatal user-callback exception"},
      {"c0000094", "integer divide-by-zero"},
      {"c0000095", "integer overflow"},
      {"c00000fd", "stack overflow"},
      {"c0000025", "noncontinuable exception"},
      {"c0000017", "no memory"},
      {"c0000420", "assertion failure"},
      {"80000003", "breakpoint"},
      {"e0434352", ".NET CLR exception"},
      {"e06d7363", "C++ exception"},
      {"c0000602", "fail-fast exception"},
      {"cfffffff", "application-defined exception"},
  };
  const auto it = kNames.find(NormCode(hexCode));
  return it == kNames.end() ? std::string() : it->second;
}

std::string FastFailName(long subcode) {
  // The FAST_FAIL_* enum from winnt.h (names without the "FAST_FAIL_" prefix).
  // These are the documented fast-fail reasons; #7 (FATAL_APP_EXIT) is the one
  // an unhandled C++/WinRT exception lands on via abort()/std::terminate().
  static const std::map<long, std::string> kFf = {
      {0, "LEGACY_GS_VIOLATION"},
      {1, "VTGUARD_CHECK_FAILURE"},
      {2, "STACK_COOKIE_CHECK_FAILURE"},
      {3, "CORRUPT_LIST_ENTRY"},
      {4, "INCORRECT_STACK"},
      {5, "INVALID_ARG"},
      {6, "GS_COOKIE_INIT"},
      {7, "FATAL_APP_EXIT"},
      {8, "RANGE_CHECK_FAILURE"},
      {9, "UNSAFE_REGISTRY_ACCESS"},
      {10, "GUARD_ICALL_CHECK_FAILURE"},
      {11, "GUARD_WRITE_CHECK_FAILURE"},
      {12, "INVALID_FIBER_SWITCH"},
      {13, "INVALID_SET_OF_CONTEXT"},
      {14, "INVALID_REFERENCE_COUNT"},
      {18, "INVALID_JUMP_BUFFER"},
      {19, "MRDATA_MODIFIED"},
      {20, "CERTIFICATION_FAILURE"},
      {21, "INVALID_EXCEPTION_CHAIN"},
      {22, "CRYPTO_LIBRARY"},
      {23, "INVALID_CALL_IN_DLL_CALLOUT"},
      {24, "INVALID_IMAGE_BASE"},
      {25, "DLOAD_PROTECTION_FAILURE"},
      {26, "UNSAFE_EXTENSION_CALL"},
      {27, "DEPRECATED_SERVICE_INVOKED"},
      {28, "INVALID_BUFFER_ACCESS"},
      {29, "INVALID_BALANCED_TREE"},
      {30, "INVALID_NEXT_THREAD"},
      {31, "GUARD_ICALL_CHECK_SUPPRESSED"},
      {32, "APCS_DISABLED"},
      {33, "INVALID_IDLE_STATE"},
      {34, "MRDATA_PROTECTION_FAILURE"},
      {35, "UNEXPECTED_HEAP_EXCEPTION"},
      {36, "INVALID_LOCK_STATE"},
      {37, "GUARD_JUMPTABLE"},
      {38, "INVALID_LONGJUMP_TARGET"},
      {39, "INVALID_DISPATCH_CONTEXT"},
      {40, "INVALID_THREAD"},
      {41, "INVALID_SYSCALL_NUMBER"},
      {42, "INVALID_FILE_OPERATION"},
      {43, "LPAC_ACCESS_DENIED"},
      {44, "GUARD_SS_FAILURE"},
      {45, "LOADER_CONTINUITY_FAILURE"},
      {46, "GUARD_EXPORT_SUPPRESSION_FAILURE"},
      {47, "INVALID_CONTROL_STACK"},
      {48, "SET_CONTEXT_DENIED"},
      {49, "INVALID_IAT"},
      {50, "HEAP_METADATA_CORRUPTION"},
      {51, "PAYLOAD_RESTRICTION_VIOLATION"},
      {52, "LOW_LABEL_ACCESS_DENIED"},
      {53, "ENCLAVE_CALL_FAILURE"},
      {54, "UNHANDLED_LSS_EXCEPTION"},
      {55, "ADMINLESS_ACCESS_DENIED"},
      {56, "UNEXPECTED_CALL"},
      {57, "CONTROL_INVALID_RETURN_ADDRESS"},
      {58, "UNEXPECTED_HOST_BEHAVIOR"},
      {59, "FLAGS_CORRUPTION"},
      {60, "VEH_CORRUPTION"},
      {61, "ETW_CORRUPTION"},
      {62, "RIO_ABORT"},
      {63, "INVALID_PFN"},
  };
  const auto it = kFf.find(subcode);
  return it == kFf.end() ? std::string() : it->second;
}

CrashSummary SummarizeCrashes(const std::vector<EventRecord> &events) {
  CrashSummary out;
  // signature key -> index into a vector (preserve first-seen fields, count up).
  std::map<std::string, size_t> index;
  std::vector<CrashSignature> sigs;
  for (const auto &e : events) {
    if (Lower(e.category) != "crash") continue;
    if (e.action.find("crash") == std::string::npos) continue;
    ++out.totalCrashes;
    CrashSignature s;
    s.image = e.imagePath.empty() ? e.target : e.imagePath;
    s.exceptionCode = NormCode(DetailOr(e, "exceptionCode"));
    s.exceptionName = ExceptionCodeName(s.exceptionCode);
    s.module = DetailOr(e, "module");
    s.moduleVersion = DetailOr(e, "moduleVersion");
    s.offset = DetailOr(e, "exceptionOffset");
    // __fastfail subcode, when the agent captured it. Accept decimal ("7") or
    // hex ("0x7"). Tolerate junk (stol throws) without unwinding the loop.
    const std::string ffRaw = DetailOr(e, "fastFailSubcode");
    if (!ffRaw.empty()) {
      try {
        const std::string n = Lower(ffRaw);
        s.fastFailSubcode = (n.rfind("0x", 0) == 0)
                                ? std::stol(n.substr(2), nullptr, 16)
                                : std::stol(n, nullptr, 0);
        s.fastFailName = FastFailName(s.fastFailSubcode);
      } catch (...) {
        s.fastFailSubcode = -1;
      }
    }
    // The subcode is part of the fault identity: the same module/offset under two
    // different fast-fail reasons is two distinct signatures.
    const std::string key = Lower(s.image) + "|" + s.exceptionCode + "|" +
                            Lower(s.module) + "|" + s.offset + "|" +
                            std::to_string(s.fastFailSubcode);
    const auto it = index.find(key);
    if (it == index.end()) {
      s.count = 1;
      index[key] = sigs.size();
      sigs.push_back(std::move(s));
    } else {
      ++sigs[it->second].count;
    }
  }
  // Sort by count desc, then by a stable signature text for determinism.
  // Total order over the FULL signature (matches the dedup key) so the sort is
  // deterministic even for signatures that differ only by faulting module --
  // std::sort isn't stable, so an incomplete tiebreak would reorder equal-keyed
  // rows across runs.
  std::sort(sigs.begin(), sigs.end(),
            [](const CrashSignature &a, const CrashSignature &b) {
              if (a.count != b.count) return a.count > b.count;
              if (a.image != b.image) return a.image < b.image;
              if (a.exceptionCode != b.exceptionCode)
                return a.exceptionCode < b.exceptionCode;
              if (a.module != b.module) return a.module < b.module;
              if (a.moduleVersion != b.moduleVersion)
                return a.moduleVersion < b.moduleVersion;
              if (a.offset != b.offset) return a.offset < b.offset;
              return a.fastFailSubcode < b.fastFailSubcode;
            });
  out.signatures = std::move(sigs);
  return out;
}

} // namespace antimal
