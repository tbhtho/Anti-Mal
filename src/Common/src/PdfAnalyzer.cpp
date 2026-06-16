#include "antimal/PdfAnalyzer.h"

#include <algorithm>
#include <cctype>
#include <utility>

namespace antimal {
namespace {

bool IsHex(uint8_t c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
uint8_t HexVal(uint8_t c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return c - 'A' + 10;
}
bool IsAlnum(uint8_t c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
// PDF token delimiters + whitespace (ISO 32000 §7.2).
bool IsDelim(uint8_t c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == 0 ||
         c == '(' || c == ')' || c == '<' || c == '>' || c == '[' || c == ']' ||
         c == '{' || c == '}' || c == '%' || c == '/';
}

// Lowercase the buffer and decode PDF name hex-escapes (/J#61vaScript ->
// /javascript) so a trivially-encoded keyword can't hide. Reports whether any
// hex-escape inside a name decoded to an alphanumeric char (the obfuscation
// tell — legitimate names never need to escape a normal letter/digit).
std::pair<std::string, bool> NormalizePdf(const std::vector<uint8_t> &d) {
  std::string out;
  out.reserve(d.size());
  bool obfuscated = false;
  bool inName = false;
  for (size_t i = 0; i < d.size(); ++i) {
    const uint8_t c = d[i];
    if (c == '/') {
      inName = true;
      out.push_back('/');
      continue;
    }
    if (c == '#' && i + 2 < d.size() && IsHex(d[i + 1]) && IsHex(d[i + 2])) {
      const uint8_t dec = static_cast<uint8_t>((HexVal(d[i + 1]) << 4) | HexVal(d[i + 2]));
      i += 2;
      if (inName && IsAlnum(dec)) obfuscated = true;
      out.push_back(static_cast<char>(std::tolower(dec)));
      continue;
    }
    if (IsDelim(c)) inName = false; // a delimiter ends the current name token
    out.push_back(static_cast<char>(std::tolower(c)));
  }
  return {std::move(out), obfuscated};
}

// Does `norm` contain `needle` (a "/name" token) as a COMPLETE token — i.e.
// followed by a PDF delimiter or end-of-buffer? Prevents /JS matching inside
// /JBIG2Decode or /jsondata.
bool HasNameToken(const std::string &norm, const std::string &needle) {
  size_t pos = 0;
  while ((pos = norm.find(needle, pos)) != std::string::npos) {
    const size_t after = pos + needle.size();
    if (after >= norm.size() ||
        IsDelim(static_cast<uint8_t>(norm[after]))) {
      return true;
    }
    pos = after;
  }
  return false;
}

bool HeaderPresent(const std::vector<uint8_t> &d) {
  const size_t n = std::min<size_t>(d.size(), 1024);
  if (n < 4) return false;
  for (size_t i = 0; i + 4 <= n; ++i) {
    if (d[i] == '%' && d[i + 1] == 'P' && d[i + 2] == 'D' && d[i + 3] == 'F') {
      return true;
    }
  }
  return false;
}

} // namespace

PdfAnalysis AnalyzePdf(const std::vector<uint8_t> &data) {
  PdfAnalysis out;
  if (!HeaderPresent(data)) {
    return out;
  }
  out.isPdf = true;

  const auto normalized = NormalizePdf(data);
  const std::string &norm = normalized.first;
  out.nameObfuscation = normalized.second;

  out.hasJavaScript =
      HasNameToken(norm, "/javascript") || HasNameToken(norm, "/js");
  out.hasAutoAction =
      HasNameToken(norm, "/openaction") || HasNameToken(norm, "/aa");
  out.hasLaunch = HasNameToken(norm, "/launch");
  out.hasEmbeddedFile = HasNameToken(norm, "/embeddedfile");
  const bool richMedia = HasNameToken(norm, "/richmedia");

  // Extract /URI action targets (the literal string after /URI). Best-effort,
  // over the original bytes so the URL's case is preserved.
  for (size_t i = 0; i + 4 < data.size() && out.uris.size() < 32; ++i) {
    if (data[i] != '/' || (data[i + 1] | 0x20) != 'u' ||
        (data[i + 2] | 0x20) != 'r' || (data[i + 3] | 0x20) != 'i') {
      continue;
    }
    size_t j = i + 4;
    while (j < data.size() &&
           (data[j] == ' ' || data[j] == '\t' || data[j] == '\r' || data[j] == '\n')) {
      ++j;
    }
    if (j < data.size() && data[j] == '(') {
      ++j;
      std::string uri;
      while (j < data.size() && data[j] != ')' && uri.size() < 2048) {
        if (data[j] == '\\' && j + 1 < data.size()) ++j; // unescape
        uri.push_back(static_cast<char>(data[j]));
        ++j;
      }
      if (!uri.empty() &&
          std::find(out.uris.begin(), out.uris.end(), uri) == out.uris.end()) {
        out.uris.push_back(uri);
      }
    }
  }

  auto add = [&](const char *id, std::string msg, int score) {
    out.findings.push_back({id, std::move(msg), score});
  };

  if (out.hasLaunch) {
    add("pdf.launch_action",
        "PDF launches an external program (/Launch action) — almost always "
        "malicious",
        35);
  }
  if (out.hasJavaScript) {
    add("pdf.javascript", "PDF carries embedded JavaScript (/JavaScript)", 30);
  }
  // An auto-trigger is only alarming when it runs code; a bare /OpenAction that
  // navigates (GoTo /Fit) is benign and routine, so gate the finding.
  if (out.hasAutoAction && (out.hasJavaScript || out.hasLaunch)) {
    add("pdf.auto_action",
        "PDF auto-executes its action on open (/OpenAction or /AA)", 20);
  }
  if (out.nameObfuscation) {
    add("pdf.name_obfuscation",
        "PDF name hex-escapes used to hide a keyword (e.g. /J#61vaScript)", 20);
  }
  if (out.hasEmbeddedFile) {
    add("pdf.embedded_file", "PDF carries an embedded file (/EmbeddedFile)", 15);
  }
  if (richMedia) {
    add("pdf.richmedia", "PDF embeds RichMedia/Flash content (/RichMedia)", 15);
  }

  return out;
}

} // namespace antimal
