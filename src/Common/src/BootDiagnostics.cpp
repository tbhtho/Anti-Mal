#include "antimal/BootDiagnostics.h"

namespace antimal {

BootOutcome ClassifyBootOutcome(const DynamicRunSummary &s) {
  BootOutcome o;

  // OS-up evidence: a session-0 agent connecting or a sample executing proves
  // the kernel + user-mode are live; a "rich" framebuffer proves a painted
  // desktop. (The agent alone is session-0, so it is NOT proof of a desktop.)
  const bool agentOrExec = s.guestAgentConnected || s.sampleExecuted;
  const bool richScreen = s.screenStateReached >= 3;
  o.reachedUserMode = s.windowsUserModeGateReached || agentOrExec || richScreen;
  o.reachedDesktop = richScreen;

  if (richScreen || agentOrExec) {
    o.stage = "desktop";
    if (richScreen && agentOrExec) {
      o.category = "desktop-reached";
      o.detail = "Desktop rendered and the guest agent/sample is live.";
    } else if (richScreen) {
      o.category = "desktop-reached";
      o.detail = "A rich (desktop-class) framebuffer was rendered.";
    } else {
      o.category = "os-up";
      o.detail = "Guest reached user mode (agent connected / sample executed); "
                 "desktop paint not confirmed by frame state.";
    }
    // The known residual even on a reached desktop.
    o.remediation =
        "If the shell is unusable, this is the documented Win11 modern-shell "
        "crash-loop; the cmd-shell fallback or a re-serviced base snapshot is "
        "the path (see CURRENT_STATE.md).";
  } else if (o.reachedUserMode) {
    o.stage = "user-mode";
    o.category = "user-mode-no-desktop";
    o.detail = "Reached user mode (OOBE/login) but no desktop frame was "
               "confirmed within the run window.";
    o.remediation = "Use the seed-boot path and allow the login/OOBE schedule "
                    "to run (interactive sessions stay alive past the agent "
                    "healthcheck); raise --timeout-sec for a cold boot.";
  } else if (s.windowsKernelReadGateReached) {
    o.stage = "kernel";
    o.category = "kernel-no-usermode";
    o.detail = "Kernel began booting (ntoskrnl read the boot disk) but did not "
               "reach user mode.";
    o.remediation = "Inspect the kernel-stage hang (1-vCPU first-logon wait or "
                    "2-vCPU AP rendezvous); use 1 vCPU for determinism.";
  } else if (s.framesCaptured > 0 || s.screenStateReached >= 1) {
    o.stage = "firmware";
    o.category = "firmware-only";
    o.detail = "Firmware/early boot rendered output but the kernel boot gate "
               "was not reached.";
    o.remediation = "Check the firmware/boot-storage contract (OVMF present, "
                    "AHCI disk attaches, BCD intact); see `doctor`.";
  } else if (s.started) {
    o.stage = "firmware";
    o.category = "no-progress";
    o.detail = "VM started but no boot-progress signal was captured.";
    o.remediation = "Confirm firmware (OVMF.fd) and a bootable base disk via "
                    "`doctor`; check serial.log / vm-diagnostics.txt.";
  } else {
    o.stage = "not-started";
    o.category = "not-started";
    o.detail = "The VM did not start.";
    o.remediation = "Run `doctor` — WHP/firmware/workspace must be ready.";
  }

  // An explicit blocker (set by the orchestrator's boot-contract checks) is the
  // most specific signal; fold it into the detail + remediation.
  if (!s.bootBlocker.empty()) {
    o.detail += " Blocker: " + s.bootBlocker + ".";
    if (!s.bootFailureStatusName.empty()) {
      o.detail += " (" + s.bootFailureStatusName + ")";
    }
  }
  return o;
}

} // namespace antimal
