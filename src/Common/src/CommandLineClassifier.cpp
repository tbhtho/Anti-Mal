#include "antimal/CommandLineClassifier.h"

#include <algorithm>
#include <cctype>

namespace antimal {
namespace {

std::string Lower(const std::string &s) {
  std::string o = s;
  std::transform(o.begin(), o.end(), o.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return o;
}

bool Has(const std::string &h, const char *n) {
  return h.find(n) != std::string::npos;
}

} // namespace

CommandLineThreat ClassifyCommandLine(const std::string &commandLine) {
  const std::string c = Lower(commandLine);
  CommandLineThreat t;
  if (c.empty()) return t;

  auto hit = [&](const char *tech, const char *why) {
    t.suspicious = true;
    t.technique = tech;
    t.reason = why;
    return t;
  };

  // Priority order: most specific / highest-signal first.
  if (Has(c, "powershell") || Has(c, "pwsh")) {
    if (Has(c, "-enc") || Has(c, "-e ") || Has(c, "encodedcommand") ||
        Has(c, "/enc")) {
      return hit("T1059.001", "encoded PowerShell command");
    }
    if (Has(c, "downloadstring") || Has(c, "downloadfile") ||
        Has(c, "net.webclient") || Has(c, "invoke-webrequest") ||
        Has(c, "iwr ") || Has(c, "start-bitstransfer") ||
        (Has(c, "iex") && Has(c, "http"))) {
      return hit("T1059.001", "PowerShell download cradle");
    }
    if (Has(c, "-nop") || Has(c, "-noprofile") || Has(c, "-w hidden") ||
        Has(c, "-windowstyle hidden") || Has(c, "-ep bypass") ||
        Has(c, "-executionpolicy bypass") || Has(c, "frombase64string")) {
      return hit("T1059.001", "hidden/bypass PowerShell");
    }
  }
  if (Has(c, "rundll32") &&
      (Has(c, "http") || Has(c, "javascript:") || Has(c, ".dll,"))) {
    return hit("T1218.011", "rundll32 proxy execution");
  }
  if (Has(c, "regsvr32") && (Has(c, "/i:http") || Has(c, "scrobj") ||
                             Has(c, "-i:http"))) {
    return hit("T1218.010", "regsvr32 scriptlet (squiblydoo)");
  }
  if (Has(c, "mshta") &&
      (Has(c, "http") || Has(c, "javascript:") || Has(c, "vbscript:"))) {
    return hit("T1218.005", "mshta remote/script execution");
  }
  if (Has(c, "certutil") &&
      (Has(c, "-urlcache") || Has(c, "-decode") || Has(c, "-f http"))) {
    return hit("T1140", "certutil download/decode");
  }
  if (Has(c, "bitsadmin") && Has(c, "/transfer")) {
    return hit("T1197", "bitsadmin transfer");
  }
  if (Has(c, "wmic") && Has(c, "process") && Has(c, "call") && Has(c, "create")) {
    return hit("T1047", "wmic process create");
  }
  if (Has(c, "vssadmin") && Has(c, "delete") && Has(c, "shadow")) {
    return hit("T1490", "shadow-copy deletion (inhibit recovery)");
  }
  if (Has(c, "wbadmin") && Has(c, "delete")) {
    return hit("T1490", "backup deletion (inhibit recovery)");
  }
  if (Has(c, "bcdedit") &&
      (Has(c, "recoveryenabled no") || Has(c, "bootstatuspolicy"))) {
    return hit("T1490", "recovery disabled via bcdedit");
  }
  if (Has(c, "schtasks") && Has(c, "/create")) {
    return hit("T1053.005", "scheduled-task creation");
  }
  if (Has(c, "sc ") && Has(c, "create")) {
    return hit("T1543.003", "service creation");
  }
  if (Has(c, "net ") && (Has(c, "user ") && Has(c, "/add"))) {
    return hit("T1136.001", "local account creation");
  }
  if (Has(c, "net ") && Has(c, "localgroup") && Has(c, "administrators") &&
      Has(c, "/add")) {
    return hit("T1098", "privilege escalation (admin group add)");
  }
  if (Has(c, "reg ") && Has(c, "add") &&
      (Has(c, "\\run") || Has(c, "currentversion\\run"))) {
    return hit("T1547.001", "registry Run-key persistence via reg.exe");
  }
  if (Has(c, "wevtutil") && Has(c, "cl ")) {
    return hit("T1070.001", "event-log clearing");
  }
  return t;
}

} // namespace antimal
