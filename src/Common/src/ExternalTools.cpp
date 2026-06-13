#include "antimal/ExternalTools.h"

#include "antimal/FileUtil.h"
#include "antimal/Subprocess.h"

#include <algorithm>
#include <regex>
#include <set>
#include <string_view>

namespace antimal {
namespace {

// Hard cap on tool output we will retain + run regexes over. Real yara/capa/diec
// output is KB-to-low-MB; this bounds memory and regex cost if a tool emits
// pathologically large output. Enforced both at the subprocess drain (so we
// never even hold more) and defensively at the top of each parser.
constexpr size_t kMaxToolOutputBytes = 16ull * 1024 * 1024;

// Best-effort JSON token finder. We don't have a full JSON parser, so we
// extract values via narrow regexes pinned to the schemas these tools emit.
// This is fragile but acceptable: each tool emits stable, well-documented
// JSON and we control the invocation flags.
std::string ExtractStringField(std::string_view json, std::string_view key) {
  const std::string pattern = std::string("\"") + std::string(key) +
                              "\"\\s*:\\s*\"([^\"\\\\]*(?:\\\\.[^\"\\\\]*)*)\"";
  std::regex re(pattern);
  std::cmatch match;
  if (std::regex_search(json.data(), json.data() + json.size(), match, re)) {
    return match[1].str();
  }
  return {};
}

std::vector<std::string> ExtractStringArrayField(std::string_view json,
                                                 std::string_view key) {
  std::vector<std::string> out;
  // Locate the array's opening '[' only; then scan forward in a depth- and
  // quote-aware way. A naive `\[([^\]]*)\]` capture breaks when a value contains
  // a literal ']' (capa emits "Foo [T1059]") or the array holds nested arrays
  // ("parts": [...]). Bounded by the array's closing bracket at depth 0.
  const std::string pattern =
      std::string("\"") + std::string(key) + "\"\\s*:\\s*\\[";
  std::regex re(pattern);
  std::cmatch match;
  if (!std::regex_search(json.data(), json.data() + json.size(), match, re)) {
    return out;
  }
  size_t pos = static_cast<size_t>(match.position(0)) +
               static_cast<size_t>(match.length(0)); // just past '['
  int depth = 1;
  while (pos < json.size() && depth > 0) {
    const char c = json[pos];
    if (c == '"') {
      std::string val;
      ++pos;
      while (pos < json.size() && json[pos] != '"') {
        if (json[pos] == '\\' && pos + 1 < json.size()) {
          ++pos; // skip the escape, keep the escaped char verbatim
        }
        val.push_back(json[pos]);
        ++pos;
      }
      ++pos; // closing quote
      out.push_back(std::move(val));
    } else if (c == '[') {
      ++depth;
      ++pos;
    } else if (c == ']') {
      --depth;
      ++pos;
    } else {
      ++pos;
    }
  }
  return out;
}

// Locate all `*.yar` and `*.yara` files under `dir`, returning a list capped
// at a reasonable size to avoid blowing up the command line.
std::vector<std::filesystem::path> CollectYaraRules(const std::filesystem::path &dir) {
  std::vector<std::filesystem::path> rules;
  std::error_code ec;
  if (!std::filesystem::exists(dir, ec) || !std::filesystem::is_directory(dir, ec)) {
    return rules;
  }
  std::filesystem::recursive_directory_iterator it(
      dir, std::filesystem::directory_options::skip_permission_denied, ec);
  std::filesystem::recursive_directory_iterator end;
  while (it != end) {
    const auto entry = *it;
    it.increment(ec);
    if (ec) { ec.clear(); continue; }
    if (!entry.is_regular_file(ec)) { ec.clear(); continue; }
    const auto ext = ToLowerAscii(entry.path().extension().string());
    if (ext == ".yar" || ext == ".yara") {
      rules.push_back(entry.path());
    }
  }
  return rules;
}

} // namespace

// =======================================================================
// YARA
// =======================================================================

YaraScanResult RunYara(const std::filesystem::path &samplePath,
                       const std::filesystem::path &rulesDir) {
  YaraScanResult result;
  const auto yaraBinary = ResolveToolPath("yara.exe");
  if (!yaraBinary) {
    return result; // available == false
  }
  result.available = true;

  const auto rules = CollectYaraRules(rulesDir);
  if (rules.empty()) {
    result.failureReason = "no .yar/.yara rules found under " + PathToUtf8(rulesDir);
    return result;
  }

  // YARA expects either a single rule file or a single combined index. We
  // emit verbose tag output (-s = strings, -m = metadata, -g = tags).
  // For multi-file rule directories, we pass each rule with -p... but the
  // common idiom is a single "index.yar" that `include`s everything. Try
  // the convention first; fall back to scanning each file independently.
  const auto indexFile = rulesDir / "index.yar";
  std::vector<std::filesystem::path> ruleFiles;
  if (std::filesystem::exists(indexFile)) {
    ruleFiles.push_back(indexFile);
  } else {
    // Cap to a reasonable number — full YARA-Forge has thousands.
    constexpr size_t kMaxRules = 512;
    ruleFiles.assign(rules.begin(),
                     rules.size() <= kMaxRules ? rules.end()
                                               : rules.begin() + kMaxRules);
  }

  // Concatenated output across all rule files.
  std::string combinedOutput;
  for (const auto &rule : ruleFiles) {
    std::vector<std::string> args = {
        "-w",                                   // suppress warnings
        "-g",                                   // show tags
        "-m",                                   // show metadata
        "-e",                                   // print absolute path
        PathToUtf8(rule),
        PathToUtf8(samplePath),
    };
    SubprocessOptions opts;
    opts.timeout = std::chrono::milliseconds(15000);
    opts.maxOutputBytes = kMaxToolOutputBytes;
    auto run = RunSubprocess(*yaraBinary, args, opts);
    if (!run.launched) {
      result.failureReason = run.failureReason;
      return result;
    }
    if (run.timedOut) {
      result.failureReason = "yara.exe timed out";
      return result;
    }
    // yara exits 0 on either "matches found" or "no matches", 1 on error.
    if (run.exitCode != 0 && !run.stdoutText.empty()) {
      // Some yara builds return non-zero with match output; tolerate.
    }
    combinedOutput += run.stdoutText;
  }

  result.matches = ParseYaraOutput(combinedOutput);
  result.succeeded = true;
  return result;
}

// =======================================================================
// capa
// =======================================================================

CapaScanResult RunCapa(const std::filesystem::path &samplePath) {
  CapaScanResult result;
  const auto capaBinary = ResolveToolPath("capa.exe");
  if (!capaBinary) {
    return result;
  }
  result.available = true;

  std::vector<std::string> args = {
      "-j",                       // JSON output
      "--quiet",
      PathToUtf8(samplePath),
  };
  SubprocessOptions opts;
  opts.timeout = std::chrono::milliseconds(60000);
  opts.maxOutputBytes = kMaxToolOutputBytes;
  auto run = RunSubprocess(*capaBinary, args, opts);
  if (!run.launched) {
    result.failureReason = run.failureReason;
    return result;
  }
  if (run.timedOut) {
    result.failureReason = "capa.exe timed out";
    return result;
  }
  // capa returns non-zero when input is unsupported (e.g. non-PE files); we
  // treat that as "no findings, not an error" because AntiMal scans broad
  // file ranges.
  if (run.stdoutText.empty()) {
    result.succeeded = true; // not an error, just nothing to say.
    return result;
  }

  result.capabilities = ParseCapaJson(run.stdoutText);
  result.succeeded = true;
  return result;
}

// =======================================================================
// Detect It Easy
// =======================================================================

DieScanResult RunDie(const std::filesystem::path &samplePath) {
  DieScanResult result;
  // diec.exe is the CLI shipped by Detect It Easy.
  const auto dieBinary = ResolveToolPath("diec.exe");
  if (!dieBinary) {
    return result;
  }
  result.available = true;

  std::vector<std::string> args = {
      "-j",                       // JSON output
      PathToUtf8(samplePath),
  };
  SubprocessOptions opts;
  opts.timeout = std::chrono::milliseconds(20000);
  opts.maxOutputBytes = kMaxToolOutputBytes;
  auto run = RunSubprocess(*dieBinary, args, opts);
  if (!run.launched) {
    result.failureReason = run.failureReason;
    return result;
  }
  if (run.timedOut) {
    result.failureReason = "diec.exe timed out";
    return result;
  }
  if (run.stdoutText.empty()) {
    result.succeeded = true;
    return result;
  }

  result.detections = ParseDieJson(run.stdoutText);
  result.succeeded = true;
  return result;
}

// --- T50: exposed, length-capped, malformed-tolerant tool-output parsers -----

std::vector<YaraMatch> ParseYaraOutput(const std::string &outputIn) {
  std::vector<YaraMatch> matches;
  std::string capped;
  const std::string &output = (outputIn.size() > kMaxToolOutputBytes)
                                  ? (capped = outputIn.substr(0, kMaxToolOutputBytes))
                                  : outputIn;
  // -g -m line: rulename [tag1,tag2] [author=foo,family=bar] /abs/path/sample.exe
  static const std::regex line(
      R"(^([A-Za-z_][\w]*)\s*(?:\[([^\]]*)\])?\s*(?:\[([^\]]*)\])?\s+(.+)$)");
  std::set<std::string> seenRules;
  std::istringstream stream(output);
  std::string text;
  while (std::getline(stream, text)) {
    // A real yara -g -m line is short; skip absurd lines so a pathological
    // single run can't blow std::regex's complexity limit.
    if (text.size() > 65536) continue;
    std::smatch m;
    bool matched = false;
    try {
      matched = std::regex_search(text, m, line);
    } catch (const std::regex_error &) {
      continue; // degrade gracefully on a complexity blowup
    }
    if (!matched) continue;
    YaraMatch match;
    match.ruleName = m[1].str();
    if (!seenRules.insert(match.ruleName).second) continue;
    if (m[2].matched && !m[2].str().empty()) {
      std::string tags = m[2].str();
      size_t pos = 0;
      while (pos < tags.size()) {
        size_t end = tags.find(',', pos);
        if (end == std::string::npos) end = tags.size();
        match.tags.push_back(Trim(tags.substr(pos, end - pos)));
        pos = end + 1;
      }
    }
    if (m[3].matched && !m[3].str().empty()) {
      std::string meta = m[3].str();
      size_t pos = 0;
      while (pos < meta.size()) {
        size_t end = meta.find(',', pos);
        if (end == std::string::npos) end = meta.size();
        match.meta.push_back(Trim(meta.substr(pos, end - pos)));
        pos = end + 1;
      }
    }
    matches.push_back(std::move(match));
  }
  return matches;
}

std::vector<CapaCapability> ParseCapaJson(const std::string &jsonIn) {
  std::vector<CapaCapability> caps;
  std::string_view json(jsonIn);
  if (json.size() > kMaxToolOutputBytes) {
    json = json.substr(0, kMaxToolOutputBytes);
  }
  // capa schema (v6): {"rules": {"<name>": {"meta": {"attack":[...],"mbc":[...],"namespace":"..."}}}}
  static const std::regex ruleStart(
      R"RE("([A-Za-z][^"]+)"\s*:\s*\{[^{]*"meta"\s*:\s*\{)RE");
  static const std::regex te(R"(T\d{4}(?:\.\d{3})?)");
  try {
    for (auto it = std::cregex_iterator(json.data(), json.data() + json.size(), ruleStart);
         it != std::cregex_iterator(); ++it) {
      CapaCapability cap;
      cap.name = (*it)[1].str();
      const size_t windowStart = static_cast<size_t>(it->position(0));
      const size_t windowEnd = std::min(json.size(), windowStart + 4096);
      std::string_view window(json.data() + windowStart, windowEnd - windowStart);
      cap.ruleNamespace = ExtractStringField(window, "namespace");
      for (const auto &a : ExtractStringArrayField(window, "attack")) {
        std::smatch tm;
        if (std::regex_search(a, tm, te)) cap.mitreTechniques.push_back(tm.str());
      }
      for (const auto &m : ExtractStringArrayField(window, "mbc")) {
        cap.mbcBehaviors.push_back(m);
      }
      auto dedupe = [](std::vector<std::string> &v) {
        std::sort(v.begin(), v.end());
        v.erase(std::unique(v.begin(), v.end()), v.end());
      };
      dedupe(cap.mitreTechniques);
      dedupe(cap.mbcBehaviors);
      caps.push_back(std::move(cap));
    }
  } catch (const std::regex_error &) {
    // pathological input hit the complexity limit: keep what we extracted.
  }
  return caps;
}

std::vector<DieDetection> ParseDieJson(const std::string &jsonIn) {
  std::vector<DieDetection> dets;
  std::string_view json(jsonIn);
  if (json.size() > kMaxToolOutputBytes) {
    json = json.substr(0, kMaxToolOutputBytes);
  }
  // DIE schema: {"detects": [{"type":"...","name":"...","version":"...","options":"..."}]}
  static const std::regex detectRe(
      R"RE(\{\s*"type"\s*:\s*"([^"]*)"\s*,\s*"name"\s*:\s*"([^"]*)"\s*(?:,\s*"version"\s*:\s*"([^"]*)")?\s*(?:,\s*"options"\s*:\s*"([^"]*)")?\s*\})RE");
  try {
    for (auto it = std::cregex_iterator(json.data(), json.data() + json.size(), detectRe);
         it != std::cregex_iterator(); ++it) {
      DieDetection d;
      d.type = (*it)[1].str();
      d.name = (*it)[2].str();
      if ((*it)[3].matched) d.version = (*it)[3].str();
      if ((*it)[4].matched) d.options = (*it)[4].str();
      dets.push_back(std::move(d));
    }
  } catch (const std::regex_error &) {
    // pathological input hit the complexity limit: keep what we extracted.
  }
  return dets;
}

} // namespace antimal
