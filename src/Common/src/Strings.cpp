#include "antimal/Strings.h"

#include "antimal/BrowserImpact.h"
#include "antimal/FileUtil.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <regex>
#include <set>
#include <string_view>

namespace antimal {
namespace {

constexpr size_t kMaxStringsPerCategory = 256;   // Cap per-IOC vector size.
constexpr size_t kMaxStringValueLength = 1024;   // Cap individual string length.

bool IsPrintableAscii(uint8_t c) {
  return c >= 0x20 && c <= 0x7E;
}

// Heuristic: looks like a domain ("foo.bar", "sub.foo.co.uk"). Rejects
// things that are clearly not (all-digits, file extensions, etc.).
bool LooksLikeDomain(std::string_view s) {
  if (s.size() < 4 || s.size() > 253) {
    return false;
  }
  size_t dotCount = 0;
  size_t labelLen = 0;
  bool labelHasAlpha = false;
  std::string lastLabel;
  std::string currentLabel;
  for (char c : s) {
    if (c == '.') {
      if (labelLen == 0 || labelLen > 63) return false;
      ++dotCount;
      lastLabel = currentLabel;
      currentLabel.clear();
      labelLen = 0;
      labelHasAlpha = false;
      continue;
    }
    const unsigned char u = static_cast<unsigned char>(c);
    if (!(std::isalnum(u) || c == '-' || c == '_')) {
      return false;
    }
    if (std::isalpha(u)) {
      labelHasAlpha = true;
    }
    currentLabel.push_back(static_cast<char>(std::tolower(u)));
    ++labelLen;
  }
  if (dotCount == 0 || labelLen == 0 || labelLen > 63) {
    return false;
  }
  // TLD must be alpha and >= 2 chars.
  for (char c : currentLabel) {
    if (!std::isalpha(static_cast<unsigned char>(c))) return false;
  }
  if (currentLabel.size() < 2) return false;
  // Filter out common file-extension-looking trailers and similar noise.
  static const std::set<std::string> kBlocked{
      "exe",  "dll",  "sys",  "bin",  "txt",  "log",  "tmp",  "dat",  "bat",
      "ps1",  "vbs",  "js",   "xml",  "json", "html", "htm",  "css",  "ico",
      "png",  "jpg",  "jpeg", "gif",  "svg",  "pdf",  "zip",  "rar",  "7z",
      "msi",  "cab",  "mui",  "lnk",  "ini",  "manifest", "config", "resx",
      "pdb",  "lib",  "obj",  "h",    "cpp",  "py",   "rb",   "go",   "rs"};
  if (kBlocked.count(currentLabel) > 0) {
    return false;
  }
  (void)labelHasAlpha;
  (void)lastLabel;
  return true;
}

bool LooksLikeIPv4(std::string_view s) {
  // Tiny hand-rolled parser. Avoid regex overhead in the hot path.
  int parts = 0;
  size_t i = 0;
  while (i < s.size()) {
    int value = 0;
    int digits = 0;
    while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) {
      value = value * 10 + (s[i] - '0');
      ++digits;
      if (digits > 3 || value > 255) return false;
      ++i;
    }
    if (digits == 0) return false;
    ++parts;
    if (i == s.size()) break;
    if (s[i] != '.') return false;
    ++i;
  }
  return parts == 4;
}

void PushDedup(std::vector<std::string> &out, std::set<std::string> &seen,
               std::string value) {
  if (value.empty() || value.size() > kMaxStringValueLength) return;
  if (out.size() >= kMaxStringsPerCategory) return;
  if (!seen.insert(value).second) return;
  out.push_back(std::move(value));
}

// Suspicious Windows API names to flag when they appear in extracted strings
// (not just in the import table, which the PE parser already covers).
const std::vector<std::string> &SuspiciousApiNeedles() {
  static const std::vector<std::string> needles = {
      "VirtualAllocEx",      "WriteProcessMemory",  "CreateRemoteThread",
      "NtCreateThreadEx",    "QueueUserAPC",        "SetWindowsHookEx",
      "GetProcAddress",      "LoadLibraryA",        "LoadLibraryW",
      "WinHttpOpen",         "InternetOpenUrl",     "URLDownloadToFile",
      "WSAStartup",          "ShellExecute",        "ShellExecuteEx",
      "CryptEncrypt",        "CryptDecrypt",        "BCryptEncrypt",
      "RegSetValueEx",       "RegCreateKey",        "SetThreadContext",
      "ZwUnmapViewOfSection", "AdjustTokenPrivileges", "ImpersonateLoggedOnUser",
      "OpenProcessToken",    "WTSEnumerateSessions", "EnumProcesses",
      "Process32First",      "Module32First",       "IsDebuggerPresent",
      "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
      "CryptStringToBinary", "VirtualProtect",      "FindResourceA",
      "FindResourceW",       "LockResource"};
  return needles;
}

} // namespace

std::vector<std::string> ExtractAsciiStrings(const std::vector<uint8_t> &data,
                                             size_t minLength) {
  std::vector<std::string> out;
  std::string current;
  current.reserve(64);
  for (uint8_t byte : data) {
    if (IsPrintableAscii(byte)) {
      current.push_back(static_cast<char>(byte));
      continue;
    }
    if (current.size() >= minLength) {
      out.push_back(std::move(current));
    }
    current.clear();
  }
  if (current.size() >= minLength) {
    out.push_back(std::move(current));
  }
  return out;
}

std::vector<std::string> ExtractUtf16Strings(const std::vector<uint8_t> &data,
                                             size_t minLength) {
  std::vector<std::string> out;
  std::string current;
  current.reserve(64);
  for (size_t i = 0; i + 1 < data.size(); i += 2) {
    const uint16_t cu = static_cast<uint16_t>(data[i]) |
                        (static_cast<uint16_t>(data[i + 1]) << 8);
    if (cu >= 0x20 && cu <= 0x7E) {
      current.push_back(static_cast<char>(cu & 0x7F));
      continue;
    }
    if (current.size() >= minLength) {
      out.push_back(std::move(current));
    }
    current.clear();
  }
  if (current.size() >= minLength) {
    out.push_back(std::move(current));
  }
  return out;
}

std::vector<std::string> ExtractAllStrings(const std::vector<uint8_t> &data,
                                           size_t minLength) {
  auto ascii = ExtractAsciiStrings(data, minLength);
  auto utf16 = ExtractUtf16Strings(data, minLength);
  ascii.insert(ascii.end(), std::make_move_iterator(utf16.begin()),
               std::make_move_iterator(utf16.end()));
  // Dedup, preserving first-seen order.
  std::set<std::string> seen;
  std::vector<std::string> out;
  out.reserve(ascii.size());
  for (auto &s : ascii) {
    if (s.size() > kMaxStringValueLength) {
      s.resize(kMaxStringValueLength);
    }
    if (seen.insert(s).second) {
      out.push_back(std::move(s));
    }
  }
  return out;
}

ExtractedIocs MineIocs(const std::vector<std::string> &strings) {
  ExtractedIocs iocs;
  std::set<std::string> urlSeen, ipSeen, domainSeen, regSeen, pathSeen, mtxSeen,
      b64Seen, apiSeen;

  // Pre-compiled regexes. std::regex is slow but the input is bounded.
  static const std::regex urlRe(
      R"((?:https?|ftp|file)://[A-Za-z0-9._\-/:?#=&%~+,@!$;]+)",
      std::regex::optimize);
  static const std::regex ipRe(R"((?:\d{1,3}\.){3}\d{1,3})", std::regex::optimize);
  static const std::regex registryRe(
      R"((?:HKLM|HKCU|HKCR|HKU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS)\\[A-Za-z0-9_\\\.\- ]{3,200})",
      std::regex::optimize | std::regex::icase);
  static const std::regex pathRe(
      R"((?:[A-Za-z]:\\|\\\\|%[A-Z_]+%\\)[A-Za-z0-9_\\\.\- ]{3,200})",
      std::regex::optimize);
  static const std::regex mutexRe(
      R"((?:Global\\|Local\\|Session\\)[A-Za-z0-9_\-{}\.]{3,128})",
      std::regex::optimize);
  static const std::regex base64Re(
      R"([A-Za-z0-9+/]{48,}={0,2})", std::regex::optimize);
  static const std::regex domainRe(
      R"([A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+)",
      std::regex::optimize);

  const auto &apiNeedles = SuspiciousApiNeedles();

  for (const auto &s : strings) {
    if (s.size() > kMaxStringValueLength) continue;

    // URLs (kept verbatim; also feed domain extraction)
    for (auto it = std::sregex_iterator(s.begin(), s.end(), urlRe);
         it != std::sregex_iterator(); ++it) {
      std::string url = it->str();
      PushDedup(iocs.urls, urlSeen, url);
      const std::string host = ExtractDomain(url);
      if (!host.empty() && LooksLikeDomain(host)) {
        PushDedup(iocs.domains, domainSeen, host);
      }
    }

    // IPs
    for (auto it = std::sregex_iterator(s.begin(), s.end(), ipRe);
         it != std::sregex_iterator(); ++it) {
      auto ip = it->str();
      if (LooksLikeIPv4(ip)) {
        PushDedup(iocs.ips, ipSeen, ip);
      }
    }

    // Bare domains (be conservative — the regex over-matches)
    for (auto it = std::sregex_iterator(s.begin(), s.end(), domainRe);
         it != std::sregex_iterator(); ++it) {
      auto domain = it->str();
      if (!LooksLikeDomain(domain)) continue;
      // Skip if the same hit is already inside a captured URL.
      bool insideUrl = false;
      for (const auto &u : iocs.urls) {
        if (u.find(domain) != std::string::npos) {
          insideUrl = true;
          break;
        }
      }
      if (!insideUrl) {
        PushDedup(iocs.domains, domainSeen,
                  std::string(domain.begin(), domain.end()));
      }
    }

    // Registry paths
    for (auto it = std::sregex_iterator(s.begin(), s.end(), registryRe);
         it != std::sregex_iterator(); ++it) {
      PushDedup(iocs.registryPaths, regSeen, it->str());
    }

    // File paths
    for (auto it = std::sregex_iterator(s.begin(), s.end(), pathRe);
         it != std::sregex_iterator(); ++it) {
      PushDedup(iocs.filePaths, pathSeen, it->str());
    }

    // Mutex hints
    for (auto it = std::sregex_iterator(s.begin(), s.end(), mutexRe);
         it != std::sregex_iterator(); ++it) {
      PushDedup(iocs.mutexHints, mtxSeen, it->str());
    }

    // Base64 blobs
    for (auto it = std::sregex_iterator(s.begin(), s.end(), base64Re);
         it != std::sregex_iterator(); ++it) {
      std::string blob = it->str();
      if (blob.size() > 256) {
        blob = blob.substr(0, 256) + "...";
      }
      PushDedup(iocs.base64Blobs, b64Seen, blob);
    }

    // Suspicious API mentions (substring search, case-insensitive)
    const std::string sLower = ToLowerAscii(s);
    for (const auto &needle : apiNeedles) {
      if (sLower.find(ToLowerAscii(needle)) != std::string::npos) {
        PushDedup(iocs.suspiciousApis, apiSeen, needle);
      }
    }
  }

  // Sort each list for stable downstream output.
  auto stableSort = [](std::vector<std::string> &v) {
    std::sort(v.begin(), v.end());
  };
  stableSort(iocs.urls);
  stableSort(iocs.ips);
  stableSort(iocs.domains);
  stableSort(iocs.registryPaths);
  stableSort(iocs.filePaths);
  stableSort(iocs.mutexHints);
  stableSort(iocs.base64Blobs);
  stableSort(iocs.suspiciousApis);
  return iocs;
}

ExtractedIocs MineIocsFromBytes(const std::vector<uint8_t> &data) {
  return MineIocs(ExtractAllStrings(data));
}

namespace {
// URL-safe byte set (RFC 3986 reserved + unreserved). We decode forward over
// these until the first non-URL byte terminates the obfuscated string.
inline bool IsUrlByte(uint8_t c) {
  if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
      (c >= '0' && c <= '9')) {
    return true;
  }
  switch (c) {
  case ':': case '/': case '?': case '#': case '[': case ']': case '@':
  case '!': case '$': case '&': case '\'': case '(': case ')': case '*':
  case '+': case ',': case ';': case '=': case '%': case '-': case '.':
  case '_': case '~':
    return true;
  default:
    return false;
  }
}
} // namespace

std::vector<ObfuscatedIoc>
MineXorObfuscatedUrls(const std::vector<uint8_t> &data) {
  std::vector<ObfuscatedIoc> out;
  constexpr size_t kMinUrl = 12;             // "http://" + >=5 host chars
  constexpr size_t kMaxUrl = kMaxStringValueLength;
  constexpr size_t kMaxScan = 32u * 1024u * 1024u; // bound pathological inputs
  constexpr size_t kMaxHits = 256;
  if (data.size() < kMinUrl) {
    return out;
  }
  const size_t n = std::min(data.size(), kMaxScan);
  std::set<std::string> seen;
  for (size_t i = 0; i + 7 < n; ++i) {
    // Single-byte key implied by aligning data[i] to 'h'. The same key must turn
    // the next three bytes into "ttp" for an "http" prefix under that key.
    const uint8_t k = static_cast<uint8_t>(data[i] ^ 'h');
    if (k == 0) {
      continue; // key 0 == plaintext; already covered by the plaintext miner.
    }
    if ((data[i + 1] ^ k) != 't' || (data[i + 2] ^ k) != 't' ||
        (data[i + 3] ^ k) != 'p') {
      continue;
    }
    // Decode forward under the implied key until a non-URL byte / length cap.
    std::string url;
    url.reserve(64);
    size_t j = i;
    for (; j < n && url.size() < kMaxUrl; ++j) {
      const uint8_t c = static_cast<uint8_t>(data[j] ^ k);
      if (!IsUrlByte(c)) {
        break;
      }
      url.push_back(static_cast<char>(c));
    }
    // Require a real scheme so a stray "http"-under-XOR run isn't a false hit.
    if (url.rfind("http://", 0) != 0 && url.rfind("https://", 0) != 0) {
      continue;
    }
    // Trim trailing punctuation that's rarely part of a URL.
    while (!url.empty()) {
      const char b = url.back();
      if (b == '.' || b == ',' || b == ';' || b == ':' || b == '\'' ||
          b == '"' || b == ')' || b == ']' || b == '}') {
        url.pop_back();
      } else {
        break;
      }
    }
    if (url.size() >= kMinUrl && seen.insert(url).second) {
      out.push_back({url, k});
      if (out.size() >= kMaxHits) {
        break;
      }
    }
    i = j; // skip past the decoded run (the for-loop ++i lands just after it).
  }
  return out;
}

} // namespace antimal
