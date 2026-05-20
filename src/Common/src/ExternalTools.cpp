#include "antimal/ExternalTools.h"

#include "antimal/FileUtil.h"
#include "antimal/Subprocess.h"

#include <algorithm>
#include <regex>
#include <set>
#include <string_view>

namespace antimal {
namespace {

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
  const std::string pattern = std::string("\"") + std::string(key) +
                              "\"\\s*:\\s*\\[([^\\]]*)\\]";
  std::regex re(pattern);
  std::cmatch match;
  if (!std::regex_search(json.data(), json.data() + json.size(), match, re)) {
    return out;
  }
  const std::string array = match[1].str();
  std::regex item("\"([^\"\\\\]*(?:\\\\.[^\"\\\\]*)*)\"");
  for (auto it = std::sregex_iterator(array.begin(), array.end(), item);
       it != std::sregex_iterator(); ++it) {
    out.push_back((*it)[1].str());
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

  // Output format with -g -m:
  //   rulename [tag1,tag2] [author="foo", family="bar"] /abs/path/sample.exe
  std::regex line(
      R"(^([A-Za-z_][\w]*)\s*(?:\[([^\]]*)\])?\s*(?:\[([^\]]*)\])?\s+(.+)$)");
  std::set<std::string> seenRules;
  std::istringstream stream(combinedOutput);
  std::string text;
  while (std::getline(stream, text)) {
    std::smatch m;
    if (!std::regex_search(text, m, line)) continue;
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
    result.matches.push_back(std::move(match));
  }
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

  // capa schema (v6): {"rules": {"<name>": {"meta": {"attack": [...], "mbc": [...], "namespace": "..."}, ...}}}
  // We extract per-rule, since each rule may have multiple ATT&CK / MBC tags.
  const std::string &out = run.stdoutText;
  // Use a custom raw-string delimiter (RE...RE) because the default
  // (...) collides with the literal `)"` that appears inside the pattern.
  std::regex ruleStart(
      R"RE("([A-Za-z][^"]+)"\s*:\s*\{[^{]*"meta"\s*:\s*\{)RE");
  for (auto it = std::sregex_iterator(out.begin(), out.end(), ruleStart);
       it != std::sregex_iterator(); ++it) {
    CapaCapability cap;
    cap.name = (*it)[1].str();
    // Read a window forward to find this rule's meta block.
    const size_t windowStart = it->position(0);
    const size_t windowEnd = std::min(out.size(), windowStart + 4096);
    std::string_view window(&out[windowStart], windowEnd - windowStart);
    cap.ruleNamespace = ExtractStringField(window, "namespace");
    // ATT&CK techniques: capa emits "T1055" or "Inject Code::Process Injection [T1055]"
    auto attack = ExtractStringArrayField(window, "attack");
    for (const auto &a : attack) {
      std::regex te(R"(T\d{4}(?:\.\d{3})?)");
      std::smatch tm;
      if (std::regex_search(a, tm, te)) {
        cap.mitreTechniques.push_back(tm.str());
      }
    }
    auto mbc = ExtractStringArrayField(window, "mbc");
    for (const auto &m : mbc) cap.mbcBehaviors.push_back(m);

    // Dedupe within a single rule.
    auto dedupe = [](std::vector<std::string> &v) {
      std::sort(v.begin(), v.end());
      v.erase(std::unique(v.begin(), v.end()), v.end());
    };
    dedupe(cap.mitreTechniques);
    dedupe(cap.mbcBehaviors);

    result.capabilities.push_back(std::move(cap));
  }
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

  // DIE schema: {"detects": [{"type":"...", "name":"...", "version":"...", "options":"..."}]}
  // Walk the detects array.
  const std::string &out = run.stdoutText;
  std::regex detectRe(
      R"RE(\{\s*"type"\s*:\s*"([^"]*)"\s*,\s*"name"\s*:\s*"([^"]*)"\s*(?:,\s*"version"\s*:\s*"([^"]*)")?\s*(?:,\s*"options"\s*:\s*"([^"]*)")?\s*\})RE");
  for (auto it = std::sregex_iterator(out.begin(), out.end(), detectRe);
       it != std::sregex_iterator(); ++it) {
    DieDetection d;
    d.type = (*it)[1].str();
    d.name = (*it)[2].str();
    if ((*it)[3].matched) d.version = (*it)[3].str();
    if ((*it)[4].matched) d.options = (*it)[4].str();
    result.detections.push_back(std::move(d));
  }
  result.succeeded = true;
  return result;
}

} // namespace antimal
