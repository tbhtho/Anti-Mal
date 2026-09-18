#include "antimal/RegistryTelemetry.h"

#include "antimal/FileUtil.h"  // UtcNowIso8601, WideToUtf8

#include <Windows.h>

namespace antimal {

namespace {

// ---------------------------------------------------------------------------
// Watched persistence-location → MITRE ATT&CK mapping (the maintainable table).
//
// Each entry pairs a stable display prefix (the prefix every snapshot key under
// that location is recorded with) to the ATT&CK technique id attributed to a
// change there. Only locations in this table are MITRE-tagged; an arbitrary
// registry write that doesn't match any prefix gets mitre="" (never fabricated).
//
// Display prefixes are guest-readable but intentionally generic ("...") — no
// product identity strings leak into anything the guest can read.
// ---------------------------------------------------------------------------
const std::vector<PersistenceLocation> kPersistenceLocations = {
    // Run / RunOnce / RunServices — registry run keys (T1547.001).
    {"HKLM\\...\\Run", "T1547.001"},
    {"HKLM\\...\\RunOnce", "T1547.001"},
    {"HKLM\\...\\RunServices", "T1547.001"},
    {"HKLM\\...\\RunServicesOnce", "T1547.001"},
    {"HKCU\\...\\Run", "T1547.001"},
    {"HKCU\\...\\RunOnce", "T1547.001"},
    {"HKCU\\...\\RunServices", "T1547.001"},
    {"HKCU\\...\\RunServicesOnce", "T1547.001"},
    // Winlogon Shell / Userinit / Notify — Winlogon helper (T1547.004).
    {"HKLM\\...\\Winlogon", "T1547.004"},
    {"HKCU\\...\\Winlogon", "T1547.004"},
    // Services ImagePath / Start — create-or-modify system process (T1543.003).
    {"HKLM\\...\\Services", "T1543.003"},
    // Image File Execution Options \\*\\Debugger — IFEO injection (T1546.012).
    {"HKLM\\...\\IFEO", "T1546.012"},
    // AppInit_DLLs / LoadAppInit_DLLs — AppInit DLLs (T1546.010).
    {"HKLM\\...\\AppInit", "T1546.010"},
    // Active Setup\\Installed Components\\*\\StubPath (T1547.014).
    {"HKLM\\...\\ActiveSetup", "T1547.014"},
    {"HKCU\\...\\ActiveSetup", "T1547.014"},
    // Shell Folders / common + per-user Startup approved (T1547.001, run-key
    // family — these are the startup-folder pointers and approved-startup state).
    {"HKLM\\...\\ShellFolders", "T1547.001"},
    {"HKCU\\...\\ShellFolders", "T1547.001"},
    {"HKLM\\...\\StartupApproved", "T1547.001"},
    {"HKCU\\...\\StartupApproved", "T1547.001"},
    // COM hijack — CLSID InprocServer32 / LocalServer32 default-value change
    // (T1546.015). Scoped to a bounded allow-list of commonly-abused CLSIDs.
    {"HKLM\\...\\COM", "T1546.015"},
    {"HKCU\\...\\COM", "T1546.015"},
};

// Marker emitted when a per-location value enumeration is capped — never a silent
// truncation. Recorded as a normal snapshot entry so it diffs like any other
// (appears once when the cap is first hit), and it carries no MITRE tag.
constexpr const char *kOverflowSuffix = "\\<more-values-truncated>";

EventRecord MakeRegEvent(const std::string &key, const std::string &data,
                         std::string action) {
  EventRecord ev;
  ev.timestampUtc = UtcNowIso8601();
  ev.source = "GuestAgent";
  ev.category = "registry";
  ev.action = std::move(action);
  ev.target = key;
  ev.details["data"] = data;
  ev.mitre = PersistenceMitreForKey(key);
  return ev;
}

}  // namespace

const std::vector<PersistenceLocation> &PersistenceLocations() {
  return kPersistenceLocations;
}

std::string PersistenceMitreForKey(const std::string &snapshotKey) {
  // Longest-prefix wins so "HKLM\\...\\RunOnce\\x" maps to the RunOnce entry,
  // not a shorter "HKLM\\...\\Run" prefix. A snapshot key is "<prefix>\\<value>",
  // so the char right after a matched prefix must be a separator (or the prefix
  // must be the whole key) — guards against "...\\Run" swallowing
  // "...\\RunServices".
  std::string bestMitre;
  size_t bestLen = 0;
  for (const auto &loc : kPersistenceLocations) {
    const std::string prefix = loc.displayPrefix;
    if (snapshotKey.size() < prefix.size() ||
        snapshotKey.compare(0, prefix.size(), prefix) != 0) {
      continue;
    }
    if (snapshotKey.size() > prefix.size() &&
        snapshotKey[prefix.size()] != '\\') {
      continue;
    }
    if (prefix.size() > bestLen) {
      bestLen = prefix.size();
      bestMitre = loc.mitre;
    }
  }
  return bestMitre;
}

std::vector<EventRecord> DiffRegistrySnapshots(const RegistrySnapshot &prev,
                                               const RegistrySnapshot &cur,
                                               bool emitBaseline,
                                               size_t baselineCap,
                                               size_t deltaCap) {
  std::vector<EventRecord> out;
  if (emitBaseline) {
    size_t n = 0;
    for (const auto &entry : cur) {
      if (n++ >= baselineCap) break;
      out.push_back(MakeRegEvent(entry.first, entry.second, "registry.value"));
    }
    return out;
  }
  size_t sets = 0;
  for (const auto &entry : cur) {
    const auto it = prev.find(entry.first);
    const bool isNew = it == prev.end();
    const bool changed = !isNew && it->second != entry.second;
    if (isNew || changed) {
      if (sets++ >= deltaCap) continue;
      out.push_back(MakeRegEvent(entry.first, entry.second, "registry.set"));
    }
  }
  for (const auto &entry : prev) {
    if (cur.find(entry.first) == cur.end()) {
      out.push_back(MakeRegEvent(entry.first, entry.second, "registry.delete"));
    }
  }
  return out;
}

namespace {

// Renders one registry value into the snapshot's string form (REG_SZ/EXPAND_SZ
// inline; everything else as a "<type N, M bytes>" placeholder).
std::string ValueToString(DWORD type, const BYTE *data, DWORD dataLen) {
  if (type == REG_SZ || type == REG_EXPAND_SZ) {
    std::wstring w(reinterpret_cast<const wchar_t *>(data),
                   dataLen / sizeof(wchar_t));
    while (!w.empty() && w.back() == L'\0') w.pop_back();
    return WideToUtf8(w);
  }
  return "<type " + std::to_string(type) + ", " + std::to_string(dataLen) +
         " bytes>";
}

// Per-location enumeration cap. These keys hold a handful of values in practice;
// the cap bounds a pathological/malicious key from making one ~2s tick walk
// thousands of values. On overflow we emit a single marker entry (no silent
// truncation). 256 comfortably exceeds any benign autostart key.
constexpr size_t kPerLocationValueCap = 256;

// Enumerates the values directly under one key into the snapshot, capped at
// kPerLocationValueCap. On overflow, records one "<more-values-truncated>"
// marker so the host sees enumeration was bounded.
void EnumKeyValues(HKEY root, const wchar_t *subKey,
                   const std::string &displayPrefix, RegistrySnapshot &out) {
  HKEY handle = nullptr;
  if (RegOpenKeyExW(root, subKey, 0, KEY_READ | KEY_WOW64_64KEY, &handle) !=
      ERROR_SUCCESS) {
    return;
  }
  size_t emitted = 0;
  for (DWORD index = 0;; ++index) {
    if (emitted >= kPerLocationValueCap) {
      out[displayPrefix + kOverflowSuffix] = "<truncated>";
      break;
    }
    wchar_t name[256];
    BYTE data[2048];
    DWORD nameLen = static_cast<DWORD>(std::size(name));
    DWORD dataLen = static_cast<DWORD>(sizeof(data));
    DWORD type = 0;
    const LONG rc = RegEnumValueW(handle, index, name, &nameLen, nullptr, &type,
                                  data, &dataLen);
    if (rc != ERROR_SUCCESS) {
      break;  // ERROR_NO_MORE_ITEMS or any error ends enumeration.
    }
    out[displayPrefix + "\\" + WideToUtf8(std::wstring(name, nameLen))] =
        ValueToString(type, data, dataLen);
    ++emitted;
  }
  RegCloseKey(handle);
}

// Reads a single named value (if present) from one key into the snapshot. Used
// for the specific high-signal values (AppInit_DLLs, Userinit, ...) where we
// want only the named value rather than every value under the key.
void CaptureNamedValue(HKEY root, const wchar_t *subKey, const wchar_t *valueName,
                       const std::string &displayKey, RegistrySnapshot &out) {
  HKEY handle = nullptr;
  if (RegOpenKeyExW(root, subKey, 0, KEY_READ | KEY_WOW64_64KEY, &handle) !=
      ERROR_SUCCESS) {
    return;
  }
  BYTE data[2048];
  DWORD dataLen = static_cast<DWORD>(sizeof(data));
  DWORD type = 0;
  if (RegQueryValueExW(handle, valueName, nullptr, &type, data, &dataLen) ==
      ERROR_SUCCESS) {
    out[displayKey] = ValueToString(type, data, dataLen);
  }
  RegCloseKey(handle);
}

// Reads the default ("(Default)") value of one key into the snapshot. Used for
// service ImagePath-style and COM InprocServer32/LocalServer32 default-value
// hijack detection.
void CaptureDefaultValue(HKEY root, const wchar_t *subKey,
                         const std::string &displayKey, RegistrySnapshot &out) {
  HKEY handle = nullptr;
  if (RegOpenKeyExW(root, subKey, 0, KEY_READ | KEY_WOW64_64KEY, &handle) !=
      ERROR_SUCCESS) {
    return;
  }
  BYTE data[2048];
  DWORD dataLen = static_cast<DWORD>(sizeof(data));
  DWORD type = 0;
  if (RegQueryValueExW(handle, nullptr, nullptr, &type, data, &dataLen) ==
      ERROR_SUCCESS) {
    out[displayKey] = ValueToString(type, data, dataLen);
  }
  RegCloseKey(handle);
}

// Snapshots the per-service ImagePath + Start (and Type) for each service
// subkey under ...\\Services, bounded by kServiceCap. Services are the noisiest
// location (hundreds on a fresh install), so the cap is generous but firm and an
// overflow marker is recorded. Only the persistence-relevant values are read
// (not every value under each service key).
constexpr size_t kServiceCap = 1024;

void CaptureServices(RegistrySnapshot &out) {
  const wchar_t *kServices = L"SYSTEM\\CurrentControlSet\\Services";
  HKEY services = nullptr;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kServices, 0,
                    KEY_READ | KEY_WOW64_64KEY, &services) != ERROR_SUCCESS) {
    return;
  }
  size_t seen = 0;
  for (DWORD index = 0;; ++index) {
    if (seen >= kServiceCap) {
      out[std::string("HKLM\\...\\Services") + kOverflowSuffix] = "<truncated>";
      break;
    }
    wchar_t name[256];
    DWORD nameLen = static_cast<DWORD>(std::size(name));
    if (RegEnumKeyExW(services, index, name, &nameLen, nullptr, nullptr,
                      nullptr, nullptr) != ERROR_SUCCESS) {
      break;
    }
    ++seen;
    const std::string svc = WideToUtf8(std::wstring(name, nameLen));
    const std::wstring svcSub = std::wstring(kServices) + L"\\" + name;
    CaptureNamedValue(HKEY_LOCAL_MACHINE, svcSub.c_str(), L"ImagePath",
                      "HKLM\\...\\Services\\" + svc + "\\ImagePath", out);
    CaptureNamedValue(HKEY_LOCAL_MACHINE, svcSub.c_str(), L"Start",
                      "HKLM\\...\\Services\\" + svc + "\\Start", out);
  }
  RegCloseKey(services);
}

// Snapshots the IFEO \\<image>\\Debugger value for each image subkey, bounded by
// kIfeoCap. Only the Debugger value is read — that is the injection signal.
constexpr size_t kIfeoCap = 512;

void CaptureIfeoDebuggers(RegistrySnapshot &out) {
  const wchar_t *kIfeo =
      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution "
      L"Options";
  HKEY ifeo = nullptr;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kIfeo, 0, KEY_READ | KEY_WOW64_64KEY,
                    &ifeo) != ERROR_SUCCESS) {
    return;
  }
  size_t seen = 0;
  for (DWORD index = 0;; ++index) {
    if (seen >= kIfeoCap) {
      out[std::string("HKLM\\...\\IFEO") + kOverflowSuffix] = "<truncated>";
      break;
    }
    wchar_t name[256];
    DWORD nameLen = static_cast<DWORD>(std::size(name));
    if (RegEnumKeyExW(ifeo, index, name, &nameLen, nullptr, nullptr, nullptr,
                      nullptr) != ERROR_SUCCESS) {
      break;
    }
    ++seen;
    const std::string img = WideToUtf8(std::wstring(name, nameLen));
    const std::wstring imgSub = std::wstring(kIfeo) + L"\\" + name;
    // Debugger is the IFEO-injection signal; GlobalFlag(SilentProcessExit) is a
    // related sibling but Debugger alone is the classic technique.
    CaptureNamedValue(HKEY_LOCAL_MACHINE, imgSub.c_str(), L"Debugger",
                      "HKLM\\...\\IFEO\\" + img + "\\Debugger", out);
  }
  RegCloseKey(ifeo);
}

// Snapshots Active Setup\\Installed Components\\*\\StubPath, bounded by
// kActiveSetupCap. Each StubPath runs once per user at logon — a persistence
// vector when a sample plants a new component.
constexpr size_t kActiveSetupCap = 512;

void CaptureActiveSetup(HKEY root, const std::string &hivePrefix,
                        RegistrySnapshot &out,
                        const std::wstring &subPrefix = {}) {
  const std::wstring kActiveSetup =
      subPrefix +
      L"SOFTWARE\\Microsoft\\Active Setup\\Installed Components";
  HKEY comps = nullptr;
  if (RegOpenKeyExW(root, kActiveSetup.c_str(), 0,
                    KEY_READ | KEY_WOW64_64KEY, &comps) != ERROR_SUCCESS) {
    return;
  }
  size_t seen = 0;
  for (DWORD index = 0;; ++index) {
    if (seen >= kActiveSetupCap) {
      out[hivePrefix + "\\...\\ActiveSetup" + kOverflowSuffix] = "<truncated>";
      break;
    }
    wchar_t name[256];
    DWORD nameLen = static_cast<DWORD>(std::size(name));
    if (RegEnumKeyExW(comps, index, name, &nameLen, nullptr, nullptr, nullptr,
                      nullptr) != ERROR_SUCCESS) {
      break;
    }
    ++seen;
    const std::string comp = WideToUtf8(std::wstring(name, nameLen));
    const std::wstring compSub = kActiveSetup + L"\\" + name;
    CaptureNamedValue(root, compSub.c_str(), L"StubPath",
                      hivePrefix + "\\...\\ActiveSetup\\" + comp + "\\StubPath",
                      out);
  }
  RegCloseKey(comps);
}

// Bounded allow-list of commonly-abused COM CLSIDs. We deliberately do NOT
// enumerate every CLSID (tens of thousands of subkeys — far too costly for a
// ~2s tick); instead we watch this fixed set's InprocServer32/LocalServer32
// default value for a hijack. The list is the well-known persistence CLSIDs
// (shell extensions, the MruPidl/UserAssist-adjacent objects, etc.).
const wchar_t *const kComHijackClsids[] = {
    L"{42aedc87-2188-41fd-b9a3-0c966feabec1}",  // MruPidlList (UserAssist)
    L"{0358b920-0ac7-461f-98f4-58e32cd89148}",  // ShellFolderView host
    L"{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}",  // Shell DWM / cdd
    L"{083863f1-70de-11d0-bd40-00a0c911ce86}",  // DirectShow Filter Mapper
    L"{f3130cdb-aa52-4c3a-ab32-85ffc23af9c1}",  // Microsoft WBEM helper
    L"{fbeb8a05-beee-4442-804e-409d6c4515e9}",  // ShellNew DefaultIcon host
    L"{4590f811-1d3a-11d0-891f-00aa004b2e24}",  // WbemLocator (WMI)
    L"{4de225bf-cf59-4cfc-85f7-68b90f185355}",  // PerfCtrs host
    L"{ddc05a5a-351a-4e06-8eaf-54ec1bc2dcea}",  // task scheduler helper
    L"{45ea75a0-a269-11d1-b5bf-0000f8051515}",  // Internet Explorer helper
};

void CaptureComHijacks(HKEY root, const std::string &hivePrefix,
                       RegistrySnapshot &out,
                       const std::wstring &subPrefix = {}) {
  for (const wchar_t *clsid : kComHijackClsids) {
    const std::string clsidUtf8 = WideToUtf8(std::wstring(clsid));
    for (const wchar_t *server : {L"InprocServer32", L"LocalServer32"}) {
      const std::wstring sub =
          subPrefix + L"SOFTWARE\\Classes\\CLSID\\" + clsid + L"\\" + server;
      const std::string serverUtf8 = WideToUtf8(std::wstring(server));
      CaptureDefaultValue(
          root, sub.c_str(),
          hivePrefix + "\\...\\COM\\" + clsidUtf8 + "\\" + serverUtf8, out);
    }
  }
}

}  // namespace

RegistrySnapshot CaptureRegistrySnapshot(const std::wstring &userSid) {
  RegistrySnapshot snap;

  // The HKCU-family locations are read from the SAMPLE user's loaded hive when
  // a SID is known (a LocalSystem agent's HKCU is SYSTEM's, not the interactive
  // user's). An empty SID keeps the legacy HKEY_CURRENT_USER behavior.
  const HKEY userRoot = userSid.empty() ? HKEY_CURRENT_USER : HKEY_USERS;
  const std::wstring userPrefix =
      userSid.empty() ? std::wstring() : userSid + L"\\";
  const auto userSub = [&userPrefix](const wchar_t *sub) {
    return userPrefix + sub;
  };

  // --- Run-key family (T1547.001) ---------------------------------------
  const wchar_t *kRun = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
  const wchar_t *kRunOnce =
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
  const wchar_t *kRunServices =
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices";
  const wchar_t *kRunServicesOnce =
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce";
  EnumKeyValues(HKEY_LOCAL_MACHINE, kRun, "HKLM\\...\\Run", snap);
  EnumKeyValues(HKEY_LOCAL_MACHINE, kRunOnce, "HKLM\\...\\RunOnce", snap);
  EnumKeyValues(HKEY_LOCAL_MACHINE, kRunServices, "HKLM\\...\\RunServices", snap);
  EnumKeyValues(HKEY_LOCAL_MACHINE, kRunServicesOnce,
                "HKLM\\...\\RunServicesOnce", snap);
  EnumKeyValues(userRoot, userSub(kRun).c_str(), "HKCU\\...\\Run", snap);
  EnumKeyValues(userRoot, userSub(kRunOnce).c_str(), "HKCU\\...\\RunOnce", snap);
  EnumKeyValues(userRoot, userSub(kRunServices).c_str(),
                "HKCU\\...\\RunServices", snap);
  EnumKeyValues(userRoot, userSub(kRunServicesOnce).c_str(),
                "HKCU\\...\\RunServicesOnce", snap);

  // --- Winlogon Shell / Userinit / Notify (T1547.004) -------------------
  const wchar_t *kWinlogon =
      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
  for (const wchar_t *v : {L"Shell", L"Userinit", L"Taskman", L"VMApplet",
                           L"AppSetup"}) {
    CaptureNamedValue(HKEY_LOCAL_MACHINE, kWinlogon, v,
                      std::string("HKLM\\...\\Winlogon\\") + WideToUtf8(v), snap);
    CaptureNamedValue(userRoot, userSub(kWinlogon).c_str(), v,
                      std::string("HKCU\\...\\Winlogon\\") + WideToUtf8(v), snap);
  }
  // Winlogon\\Notify subkeys (DLL notification packages).
  EnumKeyValues(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\"
                L"Notify",
                "HKLM\\...\\Winlogon\\Notify", snap);

  // --- Services ImagePath + Start (T1543.003) ---------------------------
  CaptureServices(snap);

  // --- IFEO \\*\\Debugger (T1546.012) -----------------------------------
  CaptureIfeoDebuggers(snap);

  // --- AppInit_DLLs / LoadAppInit_DLLs (T1546.010) ----------------------
  const wchar_t *kWindowsNt =
      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
  CaptureNamedValue(HKEY_LOCAL_MACHINE, kWindowsNt, L"AppInit_DLLs",
                    "HKLM\\...\\AppInit\\AppInit_DLLs", snap);
  CaptureNamedValue(HKEY_LOCAL_MACHINE, kWindowsNt, L"LoadAppInit_DLLs",
                    "HKLM\\...\\AppInit\\LoadAppInit_DLLs", snap);

  // --- Active Setup\\Installed Components\\*\\StubPath (T1547.014) -------
  CaptureActiveSetup(HKEY_LOCAL_MACHINE, "HKLM", snap);
  CaptureActiveSetup(userRoot, "HKCU", snap, userPrefix);

  // --- Shell Folders / common + per-user Startup approved (T1547.001) ---
  const wchar_t *kShellFoldersUser =
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell "
      L"Folders";
  const wchar_t *kShellFolders =
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders";
  for (const wchar_t *v : {L"Startup", L"Common Startup"}) {
    CaptureNamedValue(HKEY_LOCAL_MACHINE, kShellFoldersUser, v,
                      std::string("HKLM\\...\\ShellFolders\\") + WideToUtf8(v),
                      snap);
    CaptureNamedValue(HKEY_LOCAL_MACHINE, kShellFolders, v,
                      std::string("HKLM\\...\\ShellFolders\\") + WideToUtf8(v),
                      snap);
    CaptureNamedValue(userRoot, userSub(kShellFoldersUser).c_str(), v,
                      std::string("HKCU\\...\\ShellFolders\\") + WideToUtf8(v),
                      snap);
    CaptureNamedValue(userRoot, userSub(kShellFolders).c_str(), v,
                      std::string("HKCU\\...\\ShellFolders\\") + WideToUtf8(v),
                      snap);
  }
  // StartupApproved (the "approved to auto-run" state Explorer maintains).
  const wchar_t *kStartupApprovedRun =
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\"
      L"StartupApproved\\Run";
  EnumKeyValues(HKEY_LOCAL_MACHINE, kStartupApprovedRun,
                "HKLM\\...\\StartupApproved", snap);
  EnumKeyValues(userRoot, userSub(kStartupApprovedRun).c_str(),
                "HKCU\\...\\StartupApproved", snap);

  // --- COM hijack: bounded CLSID allow-list (T1546.015) -----------------
  CaptureComHijacks(HKEY_LOCAL_MACHINE, "HKLM", snap);
  CaptureComHijacks(userRoot, "HKCU", snap, userPrefix);

  return snap;
}

}  // namespace antimal
