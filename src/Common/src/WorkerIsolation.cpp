#include "antimal/WorkerIsolation.h"

#include <windows.h>

#include <algorithm>
#include <vector>

namespace antimal {
namespace {

const std::vector<std::string> kRequired = {
    "no_child_process",
    "no_extension_points",
    "no_remote_or_low_label",
    "dangerous_privileges_removed",
};

WorkerIsolationControl *FindControl(WorkerIsolationReport &report,
                                    const std::string &id) {
  for (auto &c : report.controls) {
    if (c.id == id) {
      return &c;
    }
  }
  return nullptr;
}

// Applies one control for real. Returns true when the OS call succeeded.
bool ApplyRealControl(const std::string &id, std::string *detail) {
  if (id == "no_child_process") {
    PROCESS_MITIGATION_CHILD_PROCESS_POLICY cp{};
    cp.NoChildProcessCreation = 1;
    if (SetProcessMitigationPolicy(ProcessChildProcessPolicy, &cp, sizeof(cp))) {
      return true;
    }
    *detail = "SetProcessMitigationPolicy(ChildProcess) failed, gle=" +
              std::to_string(GetLastError());
    return false;
  }
  if (id == "no_extension_points") {
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ep{};
    ep.DisableExtensionPoints = 1;
    if (SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy, &ep,
                                   sizeof(ep))) {
      return true;
    }
    *detail = "SetProcessMitigationPolicy(ExtensionPointDisable) failed, gle=" +
              std::to_string(GetLastError());
    return false;
  }
  if (id == "no_remote_or_low_label") {
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY il{};
    il.NoRemoteImages = 1;
    il.NoLowMandatoryLabelImages = 1;
    if (SetProcessMitigationPolicy(ProcessImageLoadPolicy, &il, sizeof(il))) {
      return true;
    }
    *detail = "SetProcessMitigationPolicy(ImageLoad) failed, gle=" +
              std::to_string(GetLastError());
    return false;
  }
  if (id == "dangerous_privileges_removed") {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
      *detail = "OpenProcessToken failed, gle=" +
                std::to_string(GetLastError());
      return false;
    }
    static const wchar_t *kDangerous[] = {
        SE_DEBUG_NAME,       SE_TCB_NAME,
        SE_LOAD_DRIVER_NAME, SE_BACKUP_NAME,
        SE_RESTORE_NAME,     SE_TAKE_OWNERSHIP_NAME,
        SE_IMPERSONATE_NAME, SE_ASSIGNPRIMARYTOKEN_NAME,
        SE_CREATE_TOKEN_NAME, SE_SECURITY_NAME,
        SE_SYSTEMTIME_NAME,  SE_SHUTDOWN_NAME,
        SE_MANAGE_VOLUME_NAME, SE_CREATE_PAGEFILE_NAME,
        SE_SYSTEM_ENVIRONMENT_NAME};

    // Query the privileges the token ACTUALLY holds. A name resolving on the OS
    // (LookupPrivilegeValueW) does NOT mean this token holds it, so counting
    // lookups was wrong: it reported failures for privileges that were never
    // present to begin with. Only privileges the token holds are candidates for
    // removal, and success is verified by re-querying.
    auto heldDangerousCount = [&](HANDLE h) -> int {
      DWORD len = 0;
      GetTokenInformation(h, TokenPrivileges, nullptr, 0, &len);
      if (len == 0) {
        return -1;
      }
      std::vector<BYTE> buf(len);
      if (!GetTokenInformation(h, TokenPrivileges, buf.data(), len, &len)) {
        return -1;
      }
      auto *tp = reinterpret_cast<TOKEN_PRIVILEGES *>(buf.data());
      int count = 0;
      for (const wchar_t *priv : kDangerous) {
        LUID luid{};
        if (!LookupPrivilegeValueW(nullptr, priv, &luid)) {
          continue;
        }
        for (DWORD i = 0; i < tp->PrivilegeCount; ++i) {
          if (tp->Privileges[i].Luid.LowPart == luid.LowPart &&
              tp->Privileges[i].Luid.HighPart == luid.HighPart) {
            ++count;
            break;
          }
        }
      }
      return count;
    };

    const int heldBefore = heldDangerousCount(token);
    if (heldBefore < 0) {
      CloseHandle(token);
      *detail = "GetTokenInformation(TokenPrivileges) failed";
      return false;
    }
    int removed = 0;
    for (const wchar_t *priv : kDangerous) {
      LUID luid{};
      if (!LookupPrivilegeValueW(nullptr, priv, &luid)) {
        continue;
      }
      TOKEN_PRIVILEGES tp{};
      tp.PrivilegeCount = 1;
      tp.Privileges[0].Luid = luid;
      tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
      SetLastError(ERROR_SUCCESS);
      if (AdjustTokenPrivileges(token, FALSE, &tp, 0, nullptr, nullptr) &&
          GetLastError() == ERROR_SUCCESS) {
        ++removed;
      }
    }
    const int heldAfter = heldDangerousCount(token);
    CloseHandle(token);
    if (heldAfter == 0) {
      if (heldBefore == 0) {
        *detail = "token held no dangerous privileges (nothing to remove)";
      }
      return true;
    }
    *detail = "removed " + std::to_string(removed) + " of " +
              std::to_string(heldBefore) + " held; " +
              std::to_string(heldAfter) + " still present";
    return false;
  }
  *detail = "unknown control";
  return false;
}

std::string CurrentIdentity() {
  wchar_t user[256]{};
  DWORD len = sizeof(user);
  std::string name = "unknown";
  if (GetUserNameW(user, &len)) {
    int need = WideCharToMultiByte(CP_UTF8, 0, user, -1, nullptr, 0, nullptr,
                                   nullptr);
    if (need > 0) {
      std::string out(static_cast<size_t>(need) - 1, '\0');
      WideCharToMultiByte(CP_UTF8, 0, user, -1, out.data(), need, nullptr,
                          nullptr);
      name = out;
    }
  }
  BOOL isAdmin = FALSE;
  PSID adminGroup = nullptr;
  SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
  if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
                               DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                               &adminGroup)) {
    CheckTokenMembership(nullptr, adminGroup, &isAdmin);
    FreeSid(adminGroup);
  }
  return name + (isAdmin ? " (elevated)" : " (standard)");
}

} // namespace

const std::vector<std::string> &RequiredWorkerIsolationControls() {
  return kRequired;
}

WorkerIsolationReport ApplyWorkerIsolation(
    const WorkerIsolationInjector &inject) {
  WorkerIsolationReport report;
  report.identity = CurrentIdentity();
  for (const auto &id : kRequired) {
    WorkerIsolationControl c;
    c.id = id;
    c.description = id;
    bool result = false;
    std::optional<bool> forced =
        inject ? inject(id) : std::optional<bool>{};
    if (forced.has_value()) {
      result = *forced;
      c.detail = result ? "forced success (test injector)"
                        : "forced failure (test injector)";
    } else {
      std::string detail;
      result = ApplyRealControl(id, &detail);
      c.detail = detail;
    }
    c.established = result;
    report.controls.push_back(std::move(c));
  }
  report.allRequiredEstablished = true;
  for (const auto &c : report.controls) {
    if (!c.established) {
      report.allRequiredEstablished = false;
    }
  }
  return report;
}

WorkerIsolationReport ApplyWorkerIsolation() {
  return ApplyWorkerIsolation(WorkerIsolationInjector{});
}

bool WorkerIsolationPermitsExecution(const WorkerIsolationReport &report) {
  return report.allRequiredEstablished;
}

} // namespace antimal
