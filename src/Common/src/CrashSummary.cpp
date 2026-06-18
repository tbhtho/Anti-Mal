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
    const std::string key = Lower(s.image) + "|" + s.exceptionCode + "|" +
                            Lower(s.module) + "|" + s.offset;
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
              return a.offset < b.offset;
            });
  out.signatures = std::move(sigs);
  return out;
}

} // namespace antimal
