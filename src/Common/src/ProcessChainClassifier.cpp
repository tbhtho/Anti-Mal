#include "antimal/ProcessChainClassifier.h"

#include <algorithm>
#include <cctype>
#include <map>
#include <set>

namespace antimal {

namespace {

std::string BaseLower(const std::string &path) {
  // Reduce to the lowercase base file name (the report's imagePath is usually
  // already a base name, but be robust to a full path).
  size_t slash = path.find_last_of("\\/");
  std::string b = slash == std::string::npos ? path : path.substr(slash + 1);
  for (char &c : b) c = static_cast<char>(std::tolower((unsigned char)c));
  return b;
}

bool In(const std::string &v, std::initializer_list<const char *> set) {
  for (const char *s : set) if (v == s) return true;
  return false;
}

bool IsOffice(const std::string &b) {
  return In(b, {"winword.exe", "excel.exe", "powerpnt.exe", "msaccess.exe",
                "outlook.exe", "mspub.exe", "onenote.exe", "visio.exe"});
}
bool IsBrowser(const std::string &b) {
  return In(b, {"chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
                "opera.exe", "brave.exe"});
}
bool IsScriptHost(const std::string &b) {
  return In(b, {"powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
                "mshta.exe", "cmd.exe"});
}
bool IsProxyExec(const std::string &b) {
  return In(b, {"mshta.exe", "rundll32.exe", "regsvr32.exe"});
}
bool IsShellLike(const std::string &b) {
  return In(b, {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
                "cscript.exe"});
}

} // namespace

std::vector<ProcessChainHit> ClassifyProcessChains(
    const std::vector<EventRecord> &events) {
  // PID -> image (from process.start). Last writer wins on PID reuse, which is
  // the best we can do without per-event timing; good enough for lineage.
  std::map<uint32_t, std::string> image;
  for (const auto &e : events) {
    if (e.category == "process" && e.action.find("start") != std::string::npos &&
        e.processId != 0 && !e.imagePath.empty()) {
      image[e.processId] = e.imagePath;
    }
  }

  std::vector<ProcessChainHit> out;
  std::set<std::string> seen;
  auto emit = [&](const std::string &p, const std::string &c,
                  const std::string &reason, const std::string &mitre, int sev) {
    const std::string key = p + "|" + c + "|" + reason;
    if (seen.insert(key).second) out.push_back({p, c, reason, mitre, sev});
  };

  for (const auto &e : events) {
    if (e.category != "process" || e.action.find("start") == std::string::npos)
      continue;
    if (e.parentProcessId == 0) continue;
    const auto pit = image.find(e.parentProcessId);
    if (pit == image.end()) continue;
    const std::string parent = BaseLower(pit->second);
    const std::string child = BaseLower(e.imagePath.empty() ? e.target
                                                            : e.imagePath);
    if (parent.empty() || child.empty() || parent == child) continue;

    if (IsOffice(parent) && IsScriptHost(child)) {
      emit(parent, child,
           "Office application spawned a script host / shell -- textbook "
           "malicious-document execution chain",
           "T1566.001", 3);
    } else if (IsBrowser(parent) &&
               In(child, {"powershell.exe", "pwsh.exe", "wscript.exe",
                          "cscript.exe", "mshta.exe"})) {
      emit(parent, child,
           "Browser spawned a script host -- drive-by / download-and-execute",
           "T1059", 2);
    } else if (IsProxyExec(parent) && IsShellLike(child)) {
      emit(parent, child,
           "Proxy-execution LOLBin spawned a shell -- staged execution",
           "T1218", 2);
    } else if (In(parent, {"wscript.exe", "cscript.exe", "mshta.exe"}) &&
               In(child, {"powershell.exe", "pwsh.exe", "cmd.exe"})) {
      emit(parent, child, "Script host chained into PowerShell/cmd", "T1059", 2);
    } else if (parent == "explorer.exe" &&
               In(child, {"wscript.exe", "cscript.exe", "mshta.exe"})) {
      emit(parent, child,
           "Shell launched a script host (likely a double-clicked lure)",
           "T1204.002", 2);
    }
  }
  return out;
}

} // namespace antimal
