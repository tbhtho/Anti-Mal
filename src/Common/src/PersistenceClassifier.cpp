#include "antimal/PersistenceClassifier.h"

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

bool Has(const std::string &haystack, const char *needle) {
  return haystack.find(needle) != std::string::npos;
}

} // namespace

PersistenceMatch ClassifyPersistence(const std::string &category,
                                     const std::string &target) {
  const std::string t = Lower(target);
  PersistenceMatch m;

  if (category == "registry" || Has(Lower(category), "registry")) {
    // Order matters: RunOnce before Run (Run is a substring of RunOnce paths).
    if (Has(t, "\\runonce")) {
      m = {true, "Registry RunOnce Key", "T1547.001"};
    } else if (Has(t, "currentversion\\run")) {
      m = {true, "Registry Run Key", "T1547.001"};
    } else if (Has(t, "\\winlogon\\shell") || Has(t, "\\winlogon\\userinit")) {
      m = {true, "Winlogon Shell/Userinit", "T1547.004"};
    } else if (Has(t, "image file execution options") && Has(t, "debugger")) {
      m = {true, "IFEO Debugger", "T1546.012"};
    } else if (Has(t, "\\services\\") &&
               (Has(t, "imagepath") || Has(t, "servicedll"))) {
      m = {true, "Service ImagePath/ServiceDll", "T1543.003"};
    } else if (Has(t, "appinit_dlls")) {
      m = {true, "AppInit_DLLs", "T1546.010"};
    } else if (Has(t, "\\clsid\\") &&
               (Has(t, "inprocserver32") || Has(t, "localserver32"))) {
      m = {true, "COM CLSID Hijack", "T1546.015"};
    } else if (Has(t, "\\schedule\\taskcache\\")) {
      m = {true, "Scheduled Task (registry)", "T1053.005"};
    } else if (Has(t, "\\policies\\explorer\\run")) {
      m = {true, "Policy Run Key", "T1547.001"};
    } else if (Has(t, "\\windows\\currentversion\\runservices")) {
      m = {true, "RunServices Key", "T1547.001"};
    }
  } else if (category == "file" || Has(Lower(category), "file")) {
    if (Has(t, "\\start menu\\programs\\startup\\")) {
      m = {true, "Startup Folder", "T1547.001"};
    } else if (Has(t, "\\system32\\tasks\\") || Has(t, "\\windows\\tasks\\")) {
      m = {true, "Scheduled Task (file)", "T1053.005"};
    }
  }
  return m;
}

} // namespace antimal
