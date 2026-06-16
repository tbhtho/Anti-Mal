#include "antimal/ScriptAnalyzer.h"

#include "antimal/FileUtil.h" // ToLowerAscii
#include "antimal/Strings.h"  // DecodeBase64, MineIocsFromBytes

#include <algorithm>
#include <initializer_list>
#include <utility>

namespace antimal {
namespace {

// Is this buffer plausibly a text script (vs a PE / archive / other binary)?
bool LooksLikeText(const std::vector<uint8_t> &data) {
  if (data.empty()) {
    return false;
  }
  auto starts = [&](std::initializer_list<int> sig) {
    if (data.size() < sig.size()) return false;
    size_t i = 0;
    for (int b : sig) {
      if (data[i++] != static_cast<uint8_t>(b)) return false;
    }
    return true;
  };
  if (starts({'M', 'Z'}) || starts({0x7F, 'E', 'L', 'F'}) ||
      starts({'P', 'K', 3, 4}) || starts({0xD0, 0xCF, 0x11, 0xE0}) ||
      starts({'%', 'P', 'D', 'F'}) || starts({0x1F, 0x8B}) ||
      starts({'R', 'a', 'r', '!'}) || starts({'7', 'z', 0xBC, 0xAF})) {
    return false;
  }
  // Sample up to 4 KB; require a high printable fraction. Tolerate UTF-16LE
  // (the high NUL of each ASCII code unit) by detecting it and excluding NULs.
  const size_t n = std::min<size_t>(data.size(), 4096);
  size_t nul = 0;
  for (size_t i = 0; i < n; ++i) {
    if (data[i] == 0) ++nul;
  }
  const bool utf16 = (n >= 16 && nul * 2 >= n - 8);
  size_t bad = 0, total = 0;
  for (size_t i = 0; i < n; ++i) {
    const uint8_t c = data[i];
    if (utf16 && c == 0) continue;
    ++total;
    if (c == 0x09 || c == 0x0A || c == 0x0D) continue;
    if (c >= 0x20 && c <= 0x7E) continue;
    if (c >= 0x80) continue; // possible UTF-8 multibyte / extended
    ++bad;                   // a C0 control char other than tab/CR/LF
  }
  if (total == 0) return false;
  return static_cast<double>(bad) / static_cast<double>(total) < 0.05;
}

// Decode possibly-UTF-16LE text bytes to an ASCII-folded std::string suitable
// for case-insensitive pattern matching. (IOC mining still runs over the raw
// bytes elsewhere, so non-ASCII is not lost to the report.)
std::string TextOf(const std::vector<uint8_t> &data) {
  size_t off = 0;
  bool utf16le = false;
  if (data.size() >= 2 && data[0] == 0xFF && data[1] == 0xFE) {
    utf16le = true;
    off = 2;
  } else if (data.size() >= 3 && data[0] == 0xEF && data[1] == 0xBB &&
             data[2] == 0xBF) {
    off = 3;
  } else {
    const size_t n = std::min<size_t>(data.size(), 4096);
    size_t nul = 0;
    for (size_t i = 1; i < n; i += 2) {
      if (data[i] == 0) ++nul;
    }
    if (n >= 16 && nul * 2 >= (n / 2)) utf16le = true;
  }
  std::string out;
  if (utf16le) {
    for (size_t i = off; i + 1 < data.size(); i += 2) {
      const uint16_t u =
          static_cast<uint16_t>(data[i]) | (static_cast<uint16_t>(data[i + 1]) << 8);
      out.push_back(u < 0x80 ? static_cast<char>(u) : '?');
    }
  } else {
    out.assign(reinterpret_cast<const char *>(data.data() + off),
               data.size() - off);
  }
  return out;
}

std::string Classify(const std::string &low, const std::string &extHint) {
  struct Map {
    const char *ext;
    const char *lang;
  };
  static const Map kMap[] = {
      {".ps1", "powershell"}, {".psm1", "powershell"}, {".psd1", "powershell"},
      {".vbs", "vbscript"},   {".vbe", "vbscript"},    {".js", "jscript"},
      {".jse", "jscript"},    {".bat", "batch"},       {".cmd", "batch"},
      {".hta", "hta"},        {".wsf", "wsf"},         {".sh", "shell"},
  };
  for (const auto &m : kMap) {
    if (extHint == m.ext) return m.lang;
  }
  auto c = [&](const char *n) { return low.find(n) != std::string::npos; };
  if (c("hta:application")) return "hta";
  if (c("<job") || c("<script")) return "wsf";
  if (low.rfind("#!", 0) == 0 && c("/bin/")) return "shell";
  int ps = 0, vbs = 0, js = 0, bat = 0;
  if (c("powershell") || c("new-object") || c("-encodedcommand") ||
      c("invoke-expression") || c("get-childitem") || c("$env:"))
    ++ps;
  if (c("createobject(") || c("wscript.") || c("dim ") || c("end sub") ||
      c("vbscript"))
    ++vbs;
  if (c("function(") || c("activexobject") || c("var ") || c("eval("))
    ++js;
  if (c("@echo off") || c("%~") || c("goto ") || c("setlocal"))
    ++bat;
  const int best = std::max({ps, vbs, js, bat});
  if (best == 0) return "";
  if (best == ps) return "powershell";
  if (best == vbs) return "vbscript";
  if (best == js) return "jscript";
  return "batch";
}

} // namespace

std::string DecodePowerShellEncodedCommand(const std::string &base64) {
  const std::vector<uint8_t> raw = DecodeBase64(base64);
  if (raw.empty()) {
    return {};
  }
  // PowerShell -EncodedCommand is UTF-16LE; some loaders base64 plain ASCII.
  // Decode both ways and keep whichever yields more printable text.
  auto fromUtf16 = [&]() -> std::pair<std::string, double> {
    std::string s;
    size_t printable = 0, total = 0;
    for (size_t i = 0; i + 1 < raw.size(); i += 2) {
      const uint16_t u =
          static_cast<uint16_t>(raw[i]) | (static_cast<uint16_t>(raw[i + 1]) << 8);
      if (u == 0) break;
      ++total;
      if (u < 0x80) {
        s.push_back(static_cast<char>(u));
        if (u >= 0x20 || u == 9 || u == 10 || u == 13) ++printable;
      } else {
        s.push_back('?');
      }
    }
    return {s, total ? static_cast<double>(printable) / total : 0.0};
  };
  auto fromAscii = [&]() -> std::pair<std::string, double> {
    std::string s;
    size_t printable = 0;
    for (uint8_t c : raw) {
      if (c == 0) break;
      s.push_back(static_cast<char>(c));
      if (c >= 0x20 || c == 9 || c == 10 || c == 13) ++printable;
    }
    return {s, s.empty() ? 0.0 : static_cast<double>(printable) / s.size()};
  };
  const auto u16 = fromUtf16();
  const auto asc = fromAscii();
  const bool useU16 = u16.second >= asc.second;
  const std::string &pick = useU16 ? u16.first : asc.first;
  const double score = useU16 ? u16.second : asc.second;
  if (pick.empty() || score < 0.8) {
    return {};
  }
  return pick;
}

ScriptAnalysis AnalyzeScript(const std::vector<uint8_t> &data,
                             const std::string &extensionHint) {
  ScriptAnalysis out;
  if (!LooksLikeText(data)) {
    return out;
  }
  const std::string ext = ToLowerAscii(extensionHint);
  const std::string text = TextOf(data);
  const std::string low = ToLowerAscii(text);
  out.language = Classify(low, ext);
  if (out.language.empty()) {
    return out; // text, but not a recognized script
  }
  out.isScript = true;

  auto add = [&](const char *id, std::string msg, int score) {
    out.findings.push_back({id, std::move(msg), score});
  };
  auto any = [&](std::initializer_list<const char *> needles) {
    for (auto n : needles) {
      if (low.find(n) != std::string::npos) return true;
    }
    return false;
  };

  // -- Encoded command: find -enc/-encodedcommand and decode the base64 token,
  //    recovering the hidden inner command + its C2 (one-layer deobfuscation). --
  {
    static const char *const kFlags[] = {"-encodedcommand", "-enc ", "-enc\t",
                                         " -e ", " -ec ", "/enc "};
    for (const char *f : kFlags) {
      const size_t p = low.find(f);
      if (p == std::string::npos) continue;
      size_t s = p + std::char_traits<char>::length(f);
      while (s < text.size() && (text[s] == ' ' || text[s] == '\t')) ++s;
      size_t e = s;
      while (e < text.size()) {
        const char ch = text[e];
        const bool b64 = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                         (ch >= '0' && ch <= '9') || ch == '+' || ch == '/' ||
                         ch == '=';
        if (!b64) break;
        ++e;
      }
      if (e - s >= 16) {
        const std::string token = text.substr(s, e - s);
        const std::string dec = DecodePowerShellEncodedCommand(token);
        add("script.encoded_command",
            "Base64 -EncodedCommand payload (" + std::to_string(e - s) +
                " chars)" +
                (dec.empty() ? ""
                             : " decoded to: " + (dec.size() > 160
                                                      ? dec.substr(0, 160) + "..."
                                                      : dec)),
            35);
        if (!dec.empty()) {
          out.decodedCommands.push_back(dec);
          const std::vector<uint8_t> db(dec.begin(), dec.end());
          for (const auto &u : MineIocsFromBytes(db).urls) {
            out.recoveredUrls.push_back(u);
          }
        }
        break;
      }
    }
  }

  // -- Download cradles / network fetch --
  if (any({"downloadstring", "downloadfile", "downloaddata", "net.webclient",
           "invoke-webrequest", "invoke-restmethod", "start-bitstransfer"})) {
    add("script.download_cradle",
        "Downloads content from a remote host (download cradle)", 30);
  }
  if (any({"-urlcache", "bitsadmin", "/transfer"}) ||
      (any({"certutil"}) && any({"-decode", "-urlcache", "-split"})) ||
      any({"curl ", "wget ", "(new-object net.webclient).downloadfile"})) {
    add("script.lolbin_download",
        "Uses a LOLBin (certutil/bitsadmin/curl) to fetch or decode a payload",
        30);
  }
  if (any({"xmlhttp", "winhttprequest", "msxml2", "serverxmlhttp",
           "adodb.stream"})) {
    add("script.script_download",
        "Creates a remote-download / file-write COM object (dropper)", 25);
  }

  // -- Dynamic execution --
  if (any({"invoke-expression", "iex(", "iex ", "iex\t", "| iex"})) {
    add("script.iex",
        "Executes a dynamically built command (Invoke-Expression / IEX)", 25);
  }
  if (any({"wscript.shell", "shell.application", ".run ", ".run(", ".exec(",
           "shellexecute"})) {
    add("script.shell_exec", "Launches a child process via a shell object", 25);
  }

  // -- Hidden / policy-bypass execution flags --
  if (any({"-windowstyle hidden", "-w hidden", "-executionpolicy bypass",
           "-exec bypass", "-nop -w", "-noninteractive"})) {
    add("script.hidden_execution",
        "Runs hidden / bypasses execution policy "
        "(-WindowStyle Hidden / -ExecutionPolicy Bypass)",
        20);
  }

  // -- AMSI / defense evasion --
  if (any({"amsiutils", "amsiinitfailed", "amsiscanbuffer",
           "system.management.automation.amsi"})) {
    add("script.amsi_bypass", "Attempts to disable AMSI (defense evasion)", 35);
  }

  // -- String / char-code obfuscation --
  if (any({"fromcharcode", "[char]", "-join", "frombase64string",
           "::frombase64string"})) {
    add("script.obfuscation",
        "String/char-code obfuscation "
        "(FromCharCode / -join / [char] / FromBase64String)",
        20);
  }
  if (any({"eval(", "executeglobal", "execute(", "function(p,a,c,k,e"})) {
    add("script.dynamic_eval",
        "Evaluates dynamically constructed code (eval / Execute)", 20);
  }

  // -- Persistence written by a script --
  if (any({"currentversion\\run", "reg add ", "schtasks /create",
           "new-scheduledtask", "registry::"})) {
    add("script.persistence",
        "Establishes persistence (Run key / scheduled task)", 20);
  }

  return out;
}

} // namespace antimal
