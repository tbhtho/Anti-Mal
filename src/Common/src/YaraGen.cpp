#include "antimal/YaraGen.h"

#include "antimal/Strings.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <set>
#include <sstream>
#include <unordered_set>

namespace antimal {

namespace {

// Common boilerplate that appears in almost every PE / many benign binaries --
// a rule keyed on these matches everything, so they're poison for a hunt.
// Matched as a case-insensitive substring against each candidate.
const std::array<const char *, 18> kBoilerplate = {
    "this program cannot be run in dos mode",
    "this program must be run under win32",
    "<!doctype",
    "<?xml",
    "microsoft corporation",
    "microsoft visual c++",
    "kernel32.dll",
    "advapi32.dll",
    "user32.dll",
    "ntdll.dll",
    "mscoree.dll",
    "msvcrt.dll",
    "gdi32.dll",
    "ole32.dll",
    "shell32.dll",
    "richedit",
    "assembly xmlns",
    "</assembly>"};

std::string ToLower(std::string s) {
  for (char &c : s) c = static_cast<char>(std::tolower((unsigned char)c));
  return s;
}

bool IsBoilerplate(const std::string &lower) {
  for (const char *b : kBoilerplate) {
    if (lower.find(b) != std::string::npos) return true;
  }
  return false;
}

// A YARA identifier must start with a letter/underscore and contain only
// [A-Za-z0-9_]. Sanitize an arbitrary name into one.
std::string SanitizeRuleName(const std::string &in) {
  std::string out;
  for (char c : in) {
    if (std::isalnum((unsigned char)c) || c == '_') out += c;
  }
  if (out.empty() || std::isdigit((unsigned char)out[0])) out = "r_" + out;
  return out;
}

// Escape a printable string for a YARA double-quoted text string.
std::string YaraEscape(const std::string &s) {
  std::string out;
  out.reserve(s.size() + 4);
  for (char c : s) {
    if (c == '\\' || c == '"') out += '\\';
    out += c;
  }
  return out;
}

// Distinctiveness heuristic: longer is better; reward mixed character classes
// (upper/lower/digit/punct) which signal a real token over padding; penalize
// strings that are a single repeated character. IOC-bearing strings get a large
// bonus applied by the caller.
int Distinctiveness(const std::string &s) {
  int score = static_cast<int>(s.size());
  bool up = false, lo = false, dig = false, punct = false;
  char first = s.empty() ? 0 : s[0];
  bool allSame = true;
  for (char c : s) {
    if (std::isupper((unsigned char)c)) up = true;
    else if (std::islower((unsigned char)c)) lo = true;
    else if (std::isdigit((unsigned char)c)) dig = true;
    else punct = true;
    if (c != first) allSame = false;
  }
  score += (up + lo + dig + punct) * 6;
  if (allSame) score -= 40;
  return score;
}

} // namespace

std::string GenerateYaraRule(const ScanResult &scan,
                             const std::vector<uint8_t> &bytes,
                             const YaraGenOptions &opts) {
  // Rule name.
  std::string ruleName = opts.ruleName;
  if (ruleName.empty()) {
    ruleName = "AntiMal_" +
               (scan.sha256.size() >= 12 ? scan.sha256.substr(0, 12) : "sample");
  }
  ruleName = SanitizeRuleName(ruleName);

  // Collect IOC strings first -- they're the highest-signal anchors. Mark them
  // so the ranking floats them to the top.
  std::set<std::string> iocStrings;
  const ExtractedIocs iocs = MineIocsFromBytes(bytes);
  for (const auto *vec : {&iocs.urls, &iocs.domains, &iocs.mutexHints}) {
    for (const auto &s : *vec) iocStrings.insert(s);
  }

  // Candidate strings: ASCII + UTF-16, filtered.
  std::vector<std::string> all = ExtractAllStrings(bytes, opts.minStringLen);
  struct Cand {
    std::string text;
    int score;
  };
  std::vector<Cand> cands;
  std::unordered_set<std::string> seen;
  for (auto &s : all) {
    if (s.size() < opts.minStringLen) continue;
    std::string t = s;
    if (t.size() > opts.maxStringLen) t = t.substr(0, opts.maxStringLen);
    if (!seen.insert(t).second) continue;
    const std::string lower = ToLower(t);
    if (IsBoilerplate(lower)) continue;
    int score = Distinctiveness(t);
    if (iocStrings.count(s) || iocStrings.count(t)) score += 1000; // IOC bonus
    cands.push_back({std::move(t), score});
  }
  // Deterministic: by score desc, then lexicographic asc as a stable tiebreaker.
  std::sort(cands.begin(), cands.end(), [](const Cand &a, const Cand &b) {
    if (a.score != b.score) return a.score > b.score;
    return a.text < b.text;
  });
  if (cands.size() > opts.maxStrings) cands.resize(opts.maxStrings);

  std::ostringstream out;
  out << "rule " << ruleName << " {\n";
  out << "  meta:\n";
  out << "    author = \"AntiMal\"\n";
  out << "    description = \"Auto-generated from static analysis; tune before "
         "deploying\"\n";
  if (!scan.sha256.empty()) out << "    sha256 = \"" << scan.sha256 << "\"\n";
  if (!scan.imphash.empty()) out << "    imphash = \"" << scan.imphash << "\"\n";
  if (!scan.detectedType.empty())
    out << "    file_type = \"" << YaraEscape(scan.detectedType) << "\"\n";
  out << "    filesize = " << bytes.size() << "\n";

  // filesize bound: generous (2x, rounded up to 4 KiB) so trivial padding
  // variants still match, but a wildly different size won't.
  const size_t cap = bytes.empty() ? 4096 : ((bytes.size() * 2 + 4095) & ~size_t(4095));

  if (cands.empty()) {
    // No distinctive strings survived: anchor on magic + size, note the hash.
    out << "  condition:\n";
    out << "    // No distinctive strings recovered; sha256 (meta) is the only "
           "strong anchor.\n";
    out << "    ";
    if (scan.isPe) out << "uint16(0) == 0x5A4D and ";
    out << "filesize < " << cap << "\n";
    out << "}\n";
    return out.str();
  }

  out << "  strings:\n";
  for (size_t i = 0; i < cands.size(); ++i) {
    out << "    $s" << i << " = \"" << YaraEscape(cands[i].text) << "\"\n";
  }
  // Require a meaningful fraction so a single coincidental string isn't enough,
  // but stay achievable: half the strings, clamped to [2, count].
  size_t need = std::max<size_t>(2, cands.size() / 2);
  need = std::min(need, cands.size());

  out << "  condition:\n";
  out << "    ";
  if (scan.isPe) out << "uint16(0) == 0x5A4D and ";
  out << "filesize < " << cap << " and " << need << " of ($s*)\n";
  out << "}\n";
  return out.str();
}

} // namespace antimal
