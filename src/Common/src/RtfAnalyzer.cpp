#include "antimal/RtfAnalyzer.h"

#include <algorithm>
#include <cctype>
#include <string>

namespace antimal {

namespace {

bool Contains(const std::string &hay, const char *needle) {
  return hay.find(needle) != std::string::npos;
}

// Decode up to `maxBytes` from the hex stream that follows an \objdata control
// word at `start`. RTF hex is ASCII hex digits, possibly interleaved with
// whitespace/newlines and control words; we take hex-digit pairs and stop at the
// group close '}' or the byte cap. Bounds-safe.
std::vector<uint8_t> DecodeObjdataHex(const std::string &s, size_t start,
                                      size_t maxBytes) {
  std::vector<uint8_t> out;
  int hi = -1;
  for (size_t i = start; i < s.size() && out.size() < maxBytes; ++i) {
    const char c = s[i];
    if (c == '}') break; // end of the object group
    int v;
    if (c >= '0' && c <= '9') v = c - '0';
    else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
    else continue; // skip whitespace / control words / braces
    if (hi < 0) {
      hi = v;
    } else {
      out.push_back(static_cast<uint8_t>((hi << 4) | v));
      hi = -1;
    }
  }
  return out;
}

// Case-insensitive find of an ASCII needle in a byte buffer.
bool BytesContainCi(const std::vector<uint8_t> &b, const char *needle) {
  std::string lower(b.begin(), b.end());
  for (char &c : lower) c = static_cast<char>(std::tolower((unsigned char)c));
  std::string n = needle;
  for (char &c : n) c = static_cast<char>(std::tolower((unsigned char)c));
  return lower.find(n) != std::string::npos;
}

} // namespace

RtfAnalysis AnalyzeRtf(const std::vector<uint8_t> &data) {
  RtfAnalysis a;
  // Header: "{\rtf" within the first few bytes (allow a leading BOM/space).
  std::string head(data.begin(),
                   data.begin() + std::min<size_t>(data.size(), 16));
  if (head.find("{\\rtf") == std::string::npos) return a;
  a.isRtf = true;

  const std::string s(data.begin(), data.end());

  // Count \object occurrences (control word, so followed by a non-letter).
  for (size_t pos = 0; (pos = s.find("\\object", pos)) != std::string::npos;) {
    ++a.objectCount;
    pos += 7;
  }
  a.hasOleObject = Contains(s, "\\objdata") || Contains(s, "\\objemb") ||
                   Contains(s, "\\objocx");
  a.hasAutoUpdate = Contains(s, "\\objupdate");

  // Peek the first \objdata blob's decoded header for the tell-tale markers.
  const size_t od = s.find("\\objdata");
  if (od != std::string::npos) {
    const auto decoded = DecodeObjdataHex(s, od + 8, 4096);
    // Equation Editor: the "Equation.Native" / "Equation.3" class name or the
    // CLSID {0002CE02-...} appears in the OLE object header.
    if (BytesContainCi(decoded, "equation") ||
        BytesContainCi(decoded, "\x02\xce\x02\x00")) {
      a.equationEditor = true;
    }
    // An embedded PE sits inside the OLE wrapper, so "MZ" isn't at offset 0;
    // anchor on the universal DOS-stub string (near-zero false positives over
    // random hex) rather than a bare "MZ" scan.
    if (BytesContainCi(decoded, "This program cannot be run in DOS mode")) {
      a.embeddedExecutable = true;
    }
    // OLE compound-file magic D0 CF 11 E0 A1 B1 1A E1.
    if (decoded.size() >= 8 && decoded[0] == 0xD0 && decoded[1] == 0xCF &&
        decoded[2] == 0x11 && decoded[3] == 0xE0) {
      // An embedded OLE is normal for \objdata; only note it if combined below.
      a.hasOleObject = true;
    }
    // Remote object/template load (CVE-2017-0199 / OLE2Link): the moniker carries
    // an http(s):// URL to a remote HTA/RTF/template fetched + run on open. The
    // URL may be UTF-16LE in the OLE moniker, so scan both raw and de-NUL'd.
    std::string flat(decoded.begin(), decoded.end());
    std::string deNul;
    deNul.reserve(flat.size());
    for (char c : flat) if (c != '\0') deNul.push_back(c);
    for (const std::string &hay : {flat, deNul}) {
      for (const char *scheme : {"http://", "https://"}) {
        size_t u = hay.find(scheme);
        if (u == std::string::npos) continue;
        size_t e = u;
        while (e < hay.size() && hay[e] > 0x20 && hay[e] != '"' && hay[e] != '}')
          ++e;
        std::string url = hay.substr(u, e - u);
        if (url.size() > 8 &&
            std::find(a.urls.begin(), a.urls.end(), url) == a.urls.end()) {
          a.urls.push_back(url);
          a.remoteLink = true;
        }
      }
    }
  }
  // Also catch the Equation class named in plaintext (some RTFs don't hex it).
  if (!a.equationEditor &&
      (Contains(s, "Equation.3") || Contains(s, "Equation Native"))) {
    a.equationEditor = true;
  }

  // Findings (scored to compose with the rest of the scan; an auto-updating OLE
  // object and the Equation Editor exploit are the high-signal ones).
  if (a.hasOleObject) {
    a.findings.push_back(
        {"rtf.ole_object",
         "RTF embeds an OLE object (\\objdata) -- common maldoc payload carrier",
         20});
  }
  if (a.hasAutoUpdate) {
    a.findings.push_back(
        {"rtf.objupdate",
         "RTF \\objupdate auto-runs the embedded object on open (no click)", 35});
  }
  if (a.equationEditor) {
    a.findings.push_back(
        {"rtf.equation_editor",
         "RTF embeds a Microsoft Equation Editor object -- the CVE-2017-11882 / "
         "CVE-2018-0802 exploit carrier",
         55});
  }
  if (a.embeddedExecutable) {
    a.findings.push_back(
        {"rtf.embedded_pe",
         "RTF \\objdata decodes to an embedded PE (MZ) executable", 50});
  }
  if (a.remoteLink) {
    std::string msg =
        "RTF object loads a remote URL on open (CVE-2017-0199 / OLE2Link): " +
        a.urls.front();
    a.findings.push_back({"rtf.remote_object_load", msg, 55});
  }
  return a;
}

} // namespace antimal
