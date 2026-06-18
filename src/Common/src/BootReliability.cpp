#include "antimal/BootReliability.h"

#include "antimal/BootDiagnostics.h"
#include "antimal/FileUtil.h"
#include "antimal/Report.h"

#include <fstream>

namespace antimal {

BootReliability AggregateBootReliability(const std::filesystem::path &workspaceRoot) {
  BootReliability out;
  std::error_code ec;
  // Iterate with the error_code overloads throughout (constructor AND advance AND
  // is_directory): the range-for form's operator++/is_directory() are the
  // THROWING overloads, so a permission error or a dir removed mid-enumeration
  // (TOCTOU during a live detonation writing run dirs) would throw -- violating
  // this function's documented no-throw contract and aborting the unguarded CLI.
  auto fexists = [](const std::filesystem::path &p) {
    std::error_code e;
    return std::filesystem::exists(p, e); // no-throw overload
  };
  auto it = std::filesystem::directory_iterator(workspaceRoot, ec);
  const std::filesystem::directory_iterator end;
  for (; !ec && it != end; it.increment(ec)) {
    const auto &entry = *it;
    std::error_code dec;
    if (!entry.is_directory(dec) || dec) continue;
    const std::string name = PathToUtf8(entry.path().filename());
    if (!name.empty() && name[0] == '_') continue; // _base, _intel_cache, ...

    // A run dir with a job.json but no report.json is attempted-but-incomplete
    // (host killed/crashed before finalizing). Don't drop it (that inflates the
    // numbers); recover its reach from the live events.jsonl -- GuestAgent
    // telemetry is the session-0 service, so it proves OS-up / user-mode (not
    // desktop, same rule as hostChannelBytes>0).
    const auto rpt = entry.path() / "report.json";
    if (!fexists(rpt)) {
      if (!fexists(entry.path() / "job.json")) continue;
      ++out.runs;
      ++out.incomplete;
      bool guestTelemetry = false;
      std::ifstream ev(entry.path() / "events.jsonl");
      for (std::string line; std::getline(ev, line);) {
        if (line.find("\"source\":\"GuestAgent\"") != std::string::npos) {
          guestTelemetry = true;
          break;
        }
      }
      if (guestTelemetry) {
        ++out.reachedUserMode;
        ++out.byStage["user-mode (telemetry, no report)"];
        ++out.byCategory["user-mode-no-desktop"];
        continue;
      }
      // No telemetry: recover the EARLY boot stage from vm-diagnostics.txt rather
      // than flatly calling it "incomplete". screenStateReached (the framebuffer
      // richness the run reached: 1=blank 2=sparse/boot-screen 3=rich/desktop) +
      // a fatalRip line (present only on a fault) are the evidence for a boot that
      // hung/crashed before the session-0 agent ever streamed.
      int screen = -1;
      bool fatal = false;
      {
        std::ifstream d(entry.path() / "vm-diagnostics.txt");
        for (std::string line; std::getline(d, line);) {
          if (line.rfind("screenStateReached:", 0) == 0) {
            try { screen = std::stoi(line.substr(19)); } catch (...) {}
          } else if (line.rfind("fatalRip:", 0) == 0) {
            fatal = true;  // written only when a fatal RIP was captured
          }
        }
      }
      if (screen >= 3) {  // a rich/desktop-class frame rendered
        ++out.reachedUserMode;
        ++out.byStage["rich-frame (no report)"];
        ++out.byCategory["user-mode-no-desktop"];
      } else if (screen == 2) {  // a boot/OOBE/spinner screen rendered
        ++out.byStage["boot-screen (no report)"];
        ++out.byCategory["kernel-no-usermode"];
      } else if (fatal) {  // crashed before rendering a meaningful screen
        ++out.byStage["fatal-fault (no report)"];
        ++out.byCategory["kernel-no-usermode"];
      } else {  // no telemetry, no frame, no fault recorded
        ++out.byStage["incomplete (no report)"];
        ++out.byCategory["incomplete"];
      }
      continue;
    }

    const auto report = LoadReportBestEffort(rpt);
    const BootOutcome bo = ClassifyBootOutcome(report.dynamicSummary);
    ++out.runs;
    ++out.byStage[bo.stage];
    ++out.byCategory[bo.category];
    if (!bo.remediation.empty()) ++out.byRemediation[bo.remediation];
    if (bo.reachedDesktop) ++out.reachedDesktop;
    if (bo.reachedUserMode) ++out.reachedUserMode;
  }
  return out;
}

} // namespace antimal
