#include "antimal/Tagger.h"

#include "antimal/FileUtil.h"

#include <algorithm>
#include <regex>
#include <set>
#include <sstream>

namespace antimal {
namespace {

bool ContainsIgnoreCase(const std::string &haystack, const std::string &needle) {
  if (needle.empty()) return false;
  return ToLowerAscii(haystack).find(ToLowerAscii(needle)) != std::string::npos;
}

std::vector<std::string> ParseStringArray(std::string_view jsonFragment) {
  // Pull strings between quotes inside the bracketed fragment. The fragment
  // is the content already extracted by the caller, so we don't recurse
  // into nested arrays.
  std::vector<std::string> out;
  bool inStr = false;
  std::string current;
  for (size_t i = 0; i < jsonFragment.size(); ++i) {
    const char c = jsonFragment[i];
    if (c == '"') {
      if (inStr) {
        out.push_back(std::move(current));
        current.clear();
      }
      inStr = !inStr;
      continue;
    }
    if (inStr) {
      if (c == '\\' && i + 1 < jsonFragment.size()) {
        const char next = jsonFragment[i + 1];
        if (next == '"' || next == '\\' || next == '/') {
          current.push_back(next);
          ++i;
          continue;
        }
        if (next == 'n') { current.push_back('\n'); ++i; continue; }
        if (next == 't') { current.push_back('\t'); ++i; continue; }
        // Pass through unknown escapes literally.
      }
      current.push_back(c);
    }
  }
  return out;
}

// Very small object-extractor: finds the `{ ... }` blocks at the top level
// of `rules` array in our tags.json. Tags.json is hand-authored and has a
// fixed schema (no nested objects beyond depth 1 inside a rule), so this
// shallow parse is enough.
std::vector<std::string> SplitTopLevelObjects(std::string_view jsonArray) {
  std::vector<std::string> out;
  int depth = 0;
  bool inStr = false;
  size_t objStart = 0;
  for (size_t i = 0; i < jsonArray.size(); ++i) {
    const char c = jsonArray[i];
    if (inStr) {
      if (c == '\\' && i + 1 < jsonArray.size()) { ++i; continue; }
      if (c == '"') inStr = false;
      continue;
    }
    if (c == '"') { inStr = true; continue; }
    if (c == '{') {
      if (depth == 0) objStart = i;
      ++depth;
      continue;
    }
    if (c == '}') {
      --depth;
      if (depth == 0) {
        out.emplace_back(jsonArray.substr(objStart, i - objStart + 1));
      }
      continue;
    }
  }
  return out;
}

std::string FindStringField(std::string_view obj, std::string_view key) {
  std::string pattern = "\"";
  pattern.append(key);
  pattern.append("\"\\s*:\\s*\"([^\"]*)\"");
  std::regex re(pattern);
  std::cmatch m;
  if (std::regex_search(obj.data(), obj.data() + obj.size(), m, re)) {
    return m[1].str();
  }
  return {};
}

int FindIntField(std::string_view obj, std::string_view key, int fallback) {
  std::string pattern = "\"";
  pattern.append(key);
  pattern.append("\"\\s*:\\s*(-?\\d+)");
  std::regex re(pattern);
  std::cmatch m;
  if (std::regex_search(obj.data(), obj.data() + obj.size(), m, re)) {
    return std::atoi(m[1].str().c_str());
  }
  return fallback;
}

std::vector<std::string> FindStringArrayField(std::string_view obj,
                                              std::string_view key) {
  std::string pattern = "\"";
  pattern.append(key);
  pattern.append("\"\\s*:\\s*\\[([^\\]]*)\\]");
  std::regex re(pattern);
  std::cmatch m;
  if (std::regex_search(obj.data(), obj.data() + obj.size(), m, re)) {
    return ParseStringArray(m[1].str());
  }
  return {};
}

} // namespace

bool Tagger::LoadRulesFromFile(const std::filesystem::path &rulesPath) {
  rules_.clear();
  lastError_.clear();
  if (!std::filesystem::exists(rulesPath)) {
    lastError_ = "rules file does not exist: " + PathToUtf8(rulesPath);
    return false;
  }
  std::string text;
  try {
    text = ReadTextFile(rulesPath);
  } catch (const std::exception &ex) {
    lastError_ = ex.what();
    return false;
  }
  // Locate the rules array.
  std::regex arrayRe(R"("rules"\s*:\s*\[)");
  std::smatch m;
  if (!std::regex_search(text, m, arrayRe)) {
    lastError_ = "rules file missing top-level \"rules\" array";
    return false;
  }
  size_t arrayStart = m.position(0) + m.length(0) - 1; // position of '['
  // Find matching ']'.
  int depth = 0;
  bool inStr = false;
  size_t end = arrayStart;
  for (size_t i = arrayStart; i < text.size(); ++i) {
    const char c = text[i];
    if (inStr) {
      if (c == '\\' && i + 1 < text.size()) { ++i; continue; }
      if (c == '"') inStr = false;
      continue;
    }
    if (c == '"') { inStr = true; continue; }
    if (c == '[') ++depth;
    else if (c == ']') {
      --depth;
      if (depth == 0) { end = i; break; }
    }
  }
  if (end <= arrayStart) {
    lastError_ = "unterminated rules array";
    return false;
  }
  std::string_view arrayBody(text.data() + arrayStart + 1,
                             end - arrayStart - 1);
  for (const auto &objText : SplitTopLevelObjects(arrayBody)) {
    Rule rule;
    rule.tag = FindStringField(objText, "tag");
    rule.category = FindStringField(objText, "category");
    rule.weight = FindIntField(objText, "weight", 25);
    rule.importNeedles = FindStringArrayField(objText, "imports");
    rule.findingRuleIds = FindStringArrayField(objText, "findings");
    rule.stringNeedles = FindStringArrayField(objText, "strings");
    rule.yaraRuleNeedles = FindStringArrayField(objText, "yara");
    rule.capaTechniqueNeedles = FindStringArrayField(objText, "capa");
    rule.dieNeedles = FindStringArrayField(objText, "die");
    if (rule.tag.empty()) continue;
    if (rule.category.empty()) rule.category = "capability";
    rules_.push_back(std::move(rule));
  }
  return !rules_.empty();
}

void Tagger::LoadBuiltinRules() {
  rules_.clear();
  auto add = [&](std::string tag, std::string category, int weight,
                 std::vector<std::string> imports,
                 std::vector<std::string> findings,
                 std::vector<std::string> strings,
                 std::vector<std::string> yara,
                 std::vector<std::string> capa,
                 std::vector<std::string> die) {
    Rule r;
    r.tag = std::move(tag);
    r.category = std::move(category);
    r.weight = weight;
    r.importNeedles = std::move(imports);
    r.findingRuleIds = std::move(findings);
    r.stringNeedles = std::move(strings);
    r.yaraRuleNeedles = std::move(yara);
    r.capaTechniqueNeedles = std::move(capa);
    r.dieNeedles = std::move(die);
    rules_.push_back(std::move(r));
  };

  // Built-in starter set. Maps closely to the tags in the Any.Run screenshot
  // the user referenced (stealer / netreactor / generic / etc).
  add("packed", "packer", 40, {}, {"entropy.high"}, {},
      {"packer", "packed"}, {}, {"packer"});
  add("dotnet", "language", 20, {"mscoree.dll", "mscorlib"}, {}, {"_CorExeMain"},
      {"dotnet"}, {}, {"Microsoft Visual C#", ".NET"});
  add("netreactor", "packer", 60, {}, {}, {},
      {"netreactor"}, {}, {".NET Reactor", "Reactor"});
  add("upx", "packer", 50, {}, {}, {"UPX0", "UPX1"}, {"upx"}, {}, {"UPX"});
  add("themida", "packer", 60, {}, {}, {"Themida"}, {"themida"}, {}, {"Themida"});
  add("vmprotect", "packer", 60, {}, {}, {"VMProtect"}, {"vmprotect"}, {}, {"VMProtect"});

  add("injector", "capability", 50,
      {"WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx",
       "VirtualAllocEx", "QueueUserAPC", "SetThreadContext"},
      {"imports.process_injection"}, {},
      {"injector", "inject"}, {"T1055"}, {});
  add("downloader", "capability", 40,
      {"URLDownloadToFile", "InternetOpenUrl", "WinHttpOpen",
       "WinHttpConnect", "WinHttpSendRequest"},
      {"imports.network_loader"}, {},
      {"downloader", "loader"}, {"T1105"}, {});
  add("loader", "family", 35, {}, {}, {"loader", "stub"},
      {"loader"}, {"T1620"}, {});
  add("stealer", "family", 50, {"CryptUnprotectData"}, {},
      {"login.live.com", "Cookies", "Local State", "wallet.dat",
       "Login Data", "passwords"},
      {"stealer", "infostealer"}, {"T1555", "T1539"}, {});
  add("keylogger", "capability", 45,
      {"SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState",
       "GetForegroundWindow"},
      {}, {"keylog"}, {"keylog", "keylogger"}, {"T1056"}, {});
  add("ransomware", "family", 60,
      {"BCryptEncrypt", "CryptEncrypt"},
      {}, {".locked", ".encrypted", "README", "DECRYPT", "ransom"},
      {"ransom"}, {"T1486"}, {});
  add("anti-vm", "capability", 25,
      {"IsDebuggerPresent", "CheckRemoteDebuggerPresent"},
      {}, {"VBoxService", "VMware", "Sandboxie", "Wireshark"},
      {"anti-vm", "anti-debug", "antidebug"}, {"T1497"}, {});
  add("rat", "family", 45,
      {"CreateProcessA", "CreateProcessW"},
      {}, {"command", "shell"}, {"rat", "remote-access"}, {"T1059.003"}, {});
  add("persistence", "capability", 30,
      {"RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW"},
      {"imports.registry_persistence"},
      {"\\Run", "RunOnce", "Winlogon", "Shell"},
      {"persistence"}, {"T1547"}, {});
  add("powershell-abuse", "capability", 35,
      {}, {"strings.encoded_powershell"},
      {"powershell", "EncodedCommand", "FromBase64String"},
      {"powershell"}, {"T1059.001"}, {});
  add("network-c2", "capability", 30,
      {"connect", "send", "recv"}, {},
      {"User-Agent", "POST /", "GET /"},
      {"c2", "command-and-control"}, {"T1071"}, {});
}

std::vector<TagResult> Tagger::Evaluate(const TagInputs &inputs,
                                       int minConfidence) const {
  std::vector<TagResult> results;
  if (rules_.empty()) return results;

  // Build a corpus of strings we'll search for each rule's needles.
  std::vector<std::string> stringCorpus;
  if (inputs.iocs) {
    auto append = [&](const std::vector<std::string> &v) {
      stringCorpus.insert(stringCorpus.end(), v.begin(), v.end());
    };
    append(inputs.iocs->urls);
    append(inputs.iocs->domains);
    append(inputs.iocs->filePaths);
    append(inputs.iocs->registryPaths);
    append(inputs.iocs->mutexHints);
    append(inputs.iocs->suspiciousApis);
  }
  // Importing the full string list would be more thorough, but the
  // ExtractedIocs already encode the noteworthy strings.

  std::vector<std::string> findingIds;
  std::vector<std::string> imports;
  if (inputs.scan) {
    imports = inputs.scan->imports;
    for (const auto &f : inputs.scan->findings) findingIds.push_back(f.ruleId);
  }

  for (const auto &rule : rules_) {
    TagResult tag;
    tag.tag = rule.tag;
    tag.category = rule.category;

    auto fire = [&](std::string reason) {
      tag.confidence += rule.weight;
      tag.reasons.push_back(std::move(reason));
    };

    for (const auto &needle : rule.importNeedles) {
      for (const auto &imp : imports) {
        if (ContainsIgnoreCase(imp, needle)) {
          fire("import " + imp);
          break;
        }
      }
    }
    for (const auto &needle : rule.findingRuleIds) {
      for (const auto &id : findingIds) {
        if (id == needle) {
          fire("finding " + id);
          break;
        }
      }
    }
    for (const auto &needle : rule.stringNeedles) {
      for (const auto &s : stringCorpus) {
        if (ContainsIgnoreCase(s, needle)) {
          fire("string \"" + needle + "\"");
          break;
        }
      }
    }
    if (inputs.yara) {
      for (const auto &needle : rule.yaraRuleNeedles) {
        for (const auto &m : inputs.yara->matches) {
          if (ContainsIgnoreCase(m.ruleName, needle)) {
            fire("yara " + m.ruleName);
            break;
          }
          bool tagHit = false;
          for (const auto &t : m.tags) {
            if (ContainsIgnoreCase(t, needle)) {
              fire("yara tag " + t);
              tagHit = true;
              break;
            }
          }
          if (tagHit) break;
        }
      }
    }
    if (inputs.capa) {
      for (const auto &needle : rule.capaTechniqueNeedles) {
        for (const auto &c : inputs.capa->capabilities) {
          bool hit = false;
          for (const auto &t : c.mitreTechniques) {
            if (t.find(needle) != std::string::npos) {
              fire("capa " + t);
              hit = true;
              break;
            }
          }
          if (!hit && ContainsIgnoreCase(c.name, needle)) {
            fire("capa " + c.name);
          }
        }
      }
    }
    if (inputs.die) {
      for (const auto &needle : rule.dieNeedles) {
        for (const auto &d : inputs.die->detections) {
          if (ContainsIgnoreCase(d.name, needle)) {
            fire("die " + d.name);
            break;
          }
        }
      }
    }

    tag.confidence = std::min(tag.confidence, 100);
    if (tag.confidence >= minConfidence) {
      results.push_back(std::move(tag));
    }
  }

  std::sort(results.begin(), results.end(),
            [](const TagResult &a, const TagResult &b) {
              return a.confidence > b.confidence;
            });
  return results;
}

} // namespace antimal
