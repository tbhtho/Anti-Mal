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
  std::string eventType;          // top-level EventType= (e.g. "APPCRASH")
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

// Parses an index from a key of the form "Sig[N].Name" / "Sig[N].Value".
// Returns true and fills `index` / `isName` on a match.
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

} // namespace detail

// Parses the text of a WER Report.wer (already converted to UTF-8) into a
// WerCrashInfo. Pairs Sig[N].Name with Sig[N].Value by index N, then maps the
// well-known signature names (case-insensitive) onto the structured fields.
// `valid` is true when at least an application name or exception code was
// recovered (i.e. this really was a crash report).
inline WerCrashInfo ParseWerReport(const std::string &utf8Text) {
  WerCrashInfo info;
  std::map<long, std::string> names;  // index -> Sig[N].Name value
  std::map<long, std::string> values; // index -> Sig[N].Value value

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
      if (isName) {
        names[index] = value;
      } else {
        values[index] = value;
      }
      continue;
    }

    // Top-level EventType (e.g. APPCRASH). Case-insensitive on the key.
    if (detail::WerLower(key) == "eventtype") {
      info.eventType = value;
    }
  }

  // Pair names with values by shared index N and map onto structured fields.
  for (const auto &n : names) {
    const auto vit = values.find(n.first);
    if (vit == values.end()) {
      continue;
    }
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
    }
  }

  info.valid = !info.appName.empty() || !info.exceptionCode.empty();
  return info;
}

} // namespace antimal
