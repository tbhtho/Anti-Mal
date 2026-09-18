#pragma once

// G2 execution-boundary enforcement: worker isolation as an ACHIEVED result.
//
// The handoff requires that the execution preflight separate PREREQUISITES
// (files/binaries that merely exist on the host -- base image, firmware, WHP,
// GuestAgent.exe) from ACHIEVED RUNTIME PROTECTIONS (what the detonation worker
// process was actually restricted to: no child processes, no legacy
// extension-point injection, no remote/low-label image loads, dangerous token
// privileges removed). A file being present is not a protection; a requested
// flag is not an established control.
//
// This module applies each required control and records whether it was actually
// established. Required controls FAIL CLOSED: if any is not established, the
// sample must not execute. The apply function takes an injector so tests can
// make any single control fail while the others succeed.

#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace antimal {

struct WorkerIsolationControl {
  std::string id;          // stable id ("no_child_process", ...)
  std::string description; // human-readable
  bool established = false;
  std::string detail;      // why it failed / extra evidence
};

struct WorkerIsolationReport {
  std::vector<WorkerIsolationControl> controls;
  // True only when every REQUIRED control was established.
  bool allRequiredEstablished = false;
  std::string identity;   // process/user identity the worker runs under
  std::string notes;
};

// A required control id set. The report's allRequiredEstablished is computed
// from exactly these.
const std::vector<std::string> &RequiredWorkerIsolationControls();

// Applies the worker restrictions to the CURRENT process and returns what was
// actually established. `inject` is called with each control id and returns:
//   * std::nullopt        -> run the real OS call for that control
//   * true                -> FORCE the control to report success
//   * false               -> FORCE the control to report failure
// This lets a test make exactly ONE required control fail while the others
// succeed, proving the gate is fail-closed per control.
//
// The real implementation:
//   * no_child_process        SetProcessMitigationPolicy(ChildProcess)
//   * no_extension_points     SetProcessMitigationPolicy(ExtensionPointDisable)
//   * no_remote_or_low_label  SetProcessMitigationPolicy(ImageLoad)
//   * dangerous_privileges_removed  AdjustTokenPrivileges (SE_PRIVILEGE_REMOVED)
// Failures are recorded, never silently ignored.
using WorkerIsolationInjector =
    std::function<std::optional<bool>(const std::string &controlId)>;

WorkerIsolationReport ApplyWorkerIsolation(const WorkerIsolationInjector &inject);

// Convenience: the real (no-injection) application.
WorkerIsolationReport ApplyWorkerIsolation();

// Pure predicate used by the orchestrator + tests: given a report, is execution
// permitted? Equals report.allRequiredEstablished, provided so callers never
// re-derive the policy.
bool WorkerIsolationPermitsExecution(const WorkerIsolationReport &report);

} // namespace antimal
