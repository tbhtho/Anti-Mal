#include "antimal/RegistryTelemetry.h"

#include "antimal/FileUtil.h"  // UtcNowIso8601, WideToUtf8

#include <Windows.h>

namespace antimal {

namespace {

EventRecord MakeRegEvent(const std::string &key, const std::string &data,
                         std::string action) {
  EventRecord ev;
  ev.timestampUtc = UtcNowIso8601();
  ev.source = "GuestAgent";
  ev.category = "registry";
  ev.action = std::move(action);
  ev.target = key;
  ev.details["data"] = data;
  return ev;
}

}  // namespace

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

void EnumKeyValues(HKEY root, const wchar_t *subKey,
                   const std::string &displayPrefix, RegistrySnapshot &out) {
  HKEY handle = nullptr;
  if (RegOpenKeyExW(root, subKey, 0, KEY_READ | KEY_WOW64_64KEY, &handle) !=
      ERROR_SUCCESS) {
    return;
  }
  for (DWORD index = 0;; ++index) {
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
    std::string valueStr;
    if (type == REG_SZ || type == REG_EXPAND_SZ) {
      std::wstring w(reinterpret_cast<const wchar_t *>(data),
                     dataLen / sizeof(wchar_t));
      while (!w.empty() && w.back() == L'\0') w.pop_back();
      valueStr = WideToUtf8(w);
    } else {
      valueStr = "<type " + std::to_string(type) + ", " +
                 std::to_string(dataLen) + " bytes>";
    }
    out[displayPrefix + "\\" + WideToUtf8(std::wstring(name, nameLen))] =
        valueStr;
  }
  RegCloseKey(handle);
}

}  // namespace

RegistrySnapshot CaptureRegistrySnapshot() {
  RegistrySnapshot snap;
  const wchar_t *kRun =
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
  const wchar_t *kRunOnce =
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
  const wchar_t *kWinlogon =
      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
  EnumKeyValues(HKEY_LOCAL_MACHINE, kRun, "HKLM\\...\\Run", snap);
  EnumKeyValues(HKEY_LOCAL_MACHINE, kRunOnce, "HKLM\\...\\RunOnce", snap);
  EnumKeyValues(HKEY_CURRENT_USER, kRun, "HKCU\\...\\Run", snap);
  EnumKeyValues(HKEY_CURRENT_USER, kRunOnce, "HKCU\\...\\RunOnce", snap);
  EnumKeyValues(HKEY_LOCAL_MACHINE, kWinlogon, "HKLM\\...\\Winlogon", snap);
  return snap;
}

}  // namespace antimal
