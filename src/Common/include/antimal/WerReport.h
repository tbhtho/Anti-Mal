#pragma once

// Windows Error Reporting (.wer) crash decoder.
//
// When a process crashes, WER writes a Report.wer file (UTF-16LE, INI-like
// key=value lines) describing the exact fault: which application, which
// faulting module, the exception code (e.g. c0000409 =
// STATUS_STACK_BUFFER_OVERRUN), and the offset into the faulting module.
// The in-guest agent reads those files with ordinary file I/O and turns them
// into telemetry so a diagnostic detonation surfaces the precise fault behind
// a process crash instead of only the bare exit code.
//
// This parser is pure (no OS dependencies) so it unit-tests trivially on the
// host. It consumes already-UTF-8 text; the caller is responsible for the
// UTF-16LE -> UTF-8 conversion when reading the on-disk file.
//
// The interesting fields arrive as indexed signature pairs:
//   Sig[0].Name=Application Name
//   Sig[0].Value=ShellHost.exe
//   Sig[3].Name=Fault Module Name
//   Sig[3].Value=ntdll.dll
//   ...
// plus a top-level EventType= line. The Name/Value lines for a given index N
// are paired by N (they are NOT guaranteed to be adjacent or in order), so the
// parser collects names and values per index first, then maps by the
// (case-insensitive) signature name.

#include <cctype>
#include <cstddef>
#include <map>
#include <string>

namespace antimal {

struct WerCrashInfo {
  std::string appName;            // Sig "Application Name"
  std::string faultModule;        // Sig "Fault Module Name"
  std::string faultModuleVersion; // Sig "Fault Module Version"
  std::string exceptionCode;      // Sig "Exception Code" (e.g. "c0000409")
  std::string exceptionOffset;    // Sig "Exception Offset"
  std::string eventType;          // top-level EventType= (e.g. "APPCRASH"/"BEX64")
  // The __fastfail SUBCODE (ExceptionInformation[0], == RCX at the `int 29h`),
  // when the report carries it. A fast-fail (0xC0000409) surfaces in WER as a
  // BEX/BEX64 bucket whose signature set includes a "Data" / "Exception
  // Information" field; for an explicit-parameter form we also read a
  // "Param[N].Name=Exception Information" / "Param[N].Value=<n>" pair. We only
  // accept a value from a field NAMED for exception info -- never by position --
  // so we never misread the app-name/version params as a subcode. -1 = absent.
  long fastFailSubcode = -1;
  bool valid = false;             // true when an app name or exception code was found
};

namespace detail {

// Trim ASCII whitespace + a trailing CR (the .wer is CRLF terminated; after a
// '\n' split the value still carries the '\r').
inline std::string WerTrim(const std::string &s) {
  size_t b = 0;
  size_t e = s.size();
  auto isWs = [](unsigned char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
  };
  while (b < e && isWs(static_cast<unsigned char>(s[b]))) ++b;
  while (e > b && isWs(static_cast<unsigned char>(s[e - 1]))) --e;
  return s.substr(b, e - b);
}

inline std::string WerLower(std::string s) {
  for (char &c : s) {
    c = static_cast<char>(
        std::tolower(static_cast<unsigned char>(c)));
  }
  return s;
}

// Parses an index from a key of the form "<prefix>[N].Name" / "<prefix>[N].Value"
// (prefix is "sig[" or "param[", lowercase, including the bracket). Returns true
// and fills `index` / `isName` on a match.
inline bool ParseIndexedKey(const std::string &key, const char *lowerPrefix,
                            long &index, bool &isName) {
  const std::string lower = WerLower(key);
  const size_t plen = std::char_traits<char>::length(lowerPrefix);
  if (lower.rfind(lowerPrefix, 0) != 0) {
    return false;
  }
  size_t pos = plen; // after "<prefix>["
  size_t numStart = pos;
  while (pos < lower.size() && std::isdigit(static_cast<unsigned char>(lower[pos]))) {
    ++pos;
  }
  // Real WER indices are < 100; cap the digit run so a pathological huge index
  // can't throw std::out_of_range out of std::stol (this parses semi-untrusted
  // on-disk content). >9 digits is never a legitimate index.
  if (pos == numStart || pos >= lower.size() || lower[pos] != ']' ||
      pos - numStart > 9) {
    return false;
  }
  index = std::stol(lower.substr(numStart, pos - numStart));
  ++pos; // skip ']'
  if (pos >= lower.size() || lower[pos] != '.') {
    return false;
  }
  ++pos; // skip '.'
  const std::string field = lower.substr(pos);
  if (field == "name") {
    isName = true;
    return true;
  }
  if (field == "value") {
    isName = false;
    return true;
  }
  return false;
}

// Back-compat wrapper for the original Sig[N] parser.
inline bool ParseSigKey(const std::string &key, long &index, bool &isName) {
  // Expect: Sig[<digits>].Name | Sig[<digits>].Value (case-insensitive prefix).
  const std::string lower = WerLower(key);
  if (lower.rfind("sig[", 0) != 0) {
    return false;
  }
  size_t pos = 4; // after "sig["
  size_t numStart = pos;
  while (pos < lower.size() && std::isdigit(static_cast<unsigned char>(lower[pos]))) {
    ++pos;
  }
  if (pos == numStart || pos >= lower.size() || lower[pos] != ']') {
    return false;
  }
  // Real WER Sig indices are < 100; cap the digit run so a pathological
  // "Sig[99999999999999999]" can't throw std::out_of_range out of std::stol and
  // unwind out of the SYSTEM agent's telemetry loop (this parses semi-untrusted
  // on-disk .wer content). >9 digits is never a legitimate index.
  if (pos - numStart > 9) {
    return false;
  }
  index = std::stol(lower.substr(numStart, pos - numStart));
  ++pos; // skip ']'
  if (pos >= lower.size() || lower[pos] != '.') {
    return false;
  }
  ++pos; // skip '.'
  const std::string field = lower.substr(pos);
  if (field == "name") {
    isName = true;
    return true;
  }
  if (field == "value") {
    isName = false;
    return true;
  }
  return false;
}

// True when a WER signature/parameter NAME denotes the exception-information
// block that carries a fast-fail subcode. Matched case-insensitively. We key on
// the NAME (never on a positional index) so the app-name/version params are
// never misread as a subcode.
inline bool IsExceptionInfoName(const std::string &lowerName) {
  return lowerName == "data" || lowerName == "exception information" ||
         lowerName == "additional information" ||
         lowerName == "fast fail code" || lowerName == "fastfail code" ||
         lowerName == "exceptioninformation";
}

// Parses the leading numeric token of a WER value as a long: hex when it starts
// with "0x", else decimal. Tolerates trailing junk. Returns -1 on no number
// (also -1 for a literal 0xFFFFFFFF, which is FAST_FAIL_INVALID_FAST_FAIL_CODE).
inline long ParseWerNumber(const std::string &v) {
  const std::string s = WerTrim(v);
  if (s.empty()) return -1;
  try {
    if (s.size() > 2 && (s[0] == '0') && (s[1] == 'x' || s[1] == 'X')) {
      return std::stol(s.substr(2), nullptr, 16);
    }
    if (std::isdigit(static_cast<unsigned char>(s[0]))) {
      return std::stol(s, nullptr, 10);
    }
  } catch (...) {
    return -1;
  }
  return -1;
}

} // namespace detail

// Parses the text of a WER Report.wer (already converted to UTF-8) into a
// WerCrashInfo. Pairs Sig[N].Name with Sig[N].Value by index N, then maps the
// well-known signature names (case-insensitive) onto the structured fields.
// `valid` is true when at least an application name or exception code was
// recovered (i.e. this really was a crash report).
inline WerCrashInfo ParseWerReport(const std::string &utf8Text) {
  WerCrashInfo info;
  std::map<long, std::string> names;   // index -> Sig[N].Name value
  std::map<long, std::string> values;  // index -> Sig[N].Value value
  std::map<long, std::string> pNames;  // index -> Param[N].Name value
  std::map<long, std::string> pValues; // index -> Param[N].Value value

  size_t start = 0;
  while (start <= utf8Text.size()) {
    size_t nl = utf8Text.find('\n', start);
    const size_t end = (nl == std::string::npos) ? utf8Text.size() : nl;
    const std::string line = utf8Text.substr(start, end - start);
    start = (nl == std::string::npos) ? utf8Text.size() + 1 : nl + 1;

    const size_t eq = line.find('=');
    if (eq == std::string::npos) {
      continue;
    }
    const std::string key = detail::WerTrim(line.substr(0, eq));
    const std::string value = detail::WerTrim(line.substr(eq + 1));
    if (key.empty()) {
      continue;
    }

    long index = 0;
    bool isName = false;
    if (detail::ParseSigKey(key, index, isName)) {
      (isName ? names : values)[index] = value;
      continue;
    }
    // Explicit-parameter form: Param[N].Name / Param[N].Value (some WER versions
    // emit the exception-information block this way alongside the Sig set).
    if (detail::ParseIndexedKey(key, "param[", index, isName)) {
      (isName ? pNames : pValues)[index] = value;
      continue;
    }

    // Top-level EventType (e.g. APPCRASH/BEX64). Case-insensitive on the key.
    if (detail::WerLower(key) == "eventtype") {
      info.eventType = value;
    }
  }

  // Pair names with values by shared index N and map onto structured fields.
  // Both the Sig set and the Param set are scanned for an exception-information
  // field (by NAME) to recover the __fastfail subcode.
  auto mapPairs = [&](const std::map<long, std::string> &nm,
                      const std::map<long, std::string> &vl) {
    for (const auto &n : nm) {
      const auto vit = vl.find(n.first);
      if (vit == vl.end()) continue;
      const std::string sigName = detail::WerLower(n.second);
      const std::string &sigValue = vit->second;
      if (sigName == "application name") {
        info.appName = sigValue;
      } else if (sigName == "fault module name") {
        info.faultModule = sigValue;
      } else if (sigName == "fault module version") {
        info.faultModuleVersion = sigValue;
      } else if (sigName == "exception code") {
        info.exceptionCode = sigValue;
      } else if (sigName == "exception offset") {
        info.exceptionOffset = sigValue;
      } else if (info.fastFailSubcode < 0 &&
                 detail::IsExceptionInfoName(sigName)) {
        info.fastFailSubcode = detail::ParseWerNumber(sigValue);
      }
    }
  };
  mapPairs(names, values);
  mapPairs(pNames, pValues);

  info.valid = !info.appName.empty() || !info.exceptionCode.empty();
  return info;
}

} // namespace antimal
