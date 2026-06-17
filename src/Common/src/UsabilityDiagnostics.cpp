#include "antimal/UsabilityDiagnostics.h"

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

bool Contains(const std::string &h, const char *n) {
  return h.find(n) != std::string::npos;
}

bool ActionIs(const EventRecord &e, const char *a) {
  return e.action == a || e.action.find(a) != std::string::npos;
}

bool IsShellHost(const std::string &imgLower) {
  return Contains(imgLower, "explorer.exe") ||
         Contains(imgLower, "shellexperiencehost") ||
         Contains(imgLower, "startmenuexperiencehost") ||
         Contains(imgLower, "searchhost") || Contains(imgLower, "searchapp") ||
         Contains(imgLower, "sihost") || Contains(imgLower, "shellhost") ||
         Contains(imgLower, "runtimebroker");
}

bool IsBrowser(const std::string &imgLower) {
  return Contains(imgLower, "msedge") || Contains(imgLower, "iexplore") ||
         Contains(imgLower, "chrome") || Contains(imgLower, "firefox") ||
         Contains(imgLower, "msedgewebview");
}

} // namespace

UsabilityReport ClassifyUsability(const DynamicRunSummary &s,
                                  const std::vector<EventRecord> &events) {
  UsabilityReport r;
  auto add = [&](const char *name, const std::string &status,
                 const std::string &detail) {
    r.dimensions.push_back({name, status, detail});
  };

  // Display.
  if (s.screenStateReached >= 3) {
    add("Display", "ok", "desktop-class framebuffer rendered");
  } else if (s.screenStateReached == 2 || s.framesCaptured > 0) {
    add("Display", "degraded", "painted output, but not a rich desktop");
  } else {
    add("Display", "not-observed", "no rendered frames captured");
  }

  // Keyboard / mouse input.
  if (s.keyboardScancodesInjected > 0 || s.ps2DataReads > 0 ||
      s.ps2MouseBytesRead > 0) {
    add("Keyboard/mouse input", "ok", "input injected and consumed by the guest");
  } else {
    add("Keyboard/mouse input", "not-observed", "no input exercised this run");
  }

  // Disk access (a booted frame implies the boot disk was read).
  if (s.ideReadCommands > 0 || s.ideSawRead || s.framesCaptured > 0) {
    add("Disk access", "ok", "guest read the boot disk");
  } else {
    add("Disk access", "not-observed", "");
  }

  // Process execution.
  if (s.sampleExecuted) {
    add("Process execution", "ok", "a sample/process executed in-guest");
  } else {
    add("Process execution", "not-observed",
        "boot/healthcheck only (no in-guest execution)");
  }

  // Telemetry.
  if (s.guestAgentConnected || s.eventsCaptured > 0) {
    add("Telemetry", "ok",
        std::to_string(s.eventsCaptured) + " event(s) captured");
  } else {
    add("Telemetry", "not-observed", "");
  }

  // Browser / interactive app.
  bool browser = false;
  for (const auto &e : events) {
    if (e.category == "process" && IsBrowser(Lower(e.imagePath))) browser = true;
  }
  add("Browser / interactive app", browser ? "ok" : "not-observed",
      browser ? "a browser process launched in-guest" : "");

  // Windows shell / File Explorer health -- the known wall.
  int shellCrashes = 0;
  for (const auto &e : events) {
    if (ActionIs(e, "process.crash") && IsShellHost(Lower(e.imagePath))) {
      ++shellCrashes;
    }
  }
  if (shellCrashes >= 3) {
    r.shellCrashLoop = true;
    add("Windows shell (File Explorer)", "crash-loop",
        "modern shell crash-looped (" + std::to_string(shellCrashes) +
            " crashes) -- File Explorer unusable");
  } else if (shellCrashes > 0) {
    add("Windows shell (File Explorer)", "degraded",
        std::to_string(shellCrashes) + " shell crash(es) observed");
  } else {
    add("Windows shell (File Explorer)", "not-observed",
        "no shell-crash telemetry (shell may not have been exercised)");
  }

  // Overall + remediation.
  int okCount = 0;
  for (const auto &d : r.dimensions) {
    if (d.status == "ok") ++okCount;
  }
  if (s.framesCaptured == 0 && s.screenStateReached == 0 && !s.guestAgentConnected) {
    r.overall = "no-boot";
    r.remediation = "Run `doctor`/`boot-report`; the guest did not reach a usable "
                    "state this run.";
  } else if (r.shellCrashLoop) {
    r.overall = "shell-degraded";
    r.remediation =
        "Modern-shell (explorer/ShellHost) crash-loop is the known Win11 wall. "
        "Use the cmd-shell sidestep (ANTIMAL_PROBE_SHELL_CMD) for a working "
        "console + app/browser launch; a re-serviced base snapshot is the real "
        "fix (see CURRENT_STATE.md).";
  } else if (okCount >= 4) {
    r.overall = "usable";
  } else {
    r.overall = "limited";
    r.remediation = "Exercise more of the guest (interactive session / detonation) "
                    "to confirm the remaining dimensions.";
  }
  return r;
}

} // namespace antimal
