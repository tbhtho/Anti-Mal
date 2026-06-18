#include "antimal/BootReliability.h"

#include "antimal/BootDiagnostics.h"
#include "antimal/FileUtil.h"
#include "antimal/Report.h"

#include <fstream>

namespace antimal {

BootReliability AggregateBootReliability(const std::filesystem::path &workspaceRoot) {
  BootReliability out;
  std::error_code ec;
  for (const auto &entry :
       std::filesystem::directory_iterator(workspaceRoot, ec)) {
    if (!entry.is_directory()) continue;
    const std::string name = PathToUtf8(entry.path().filename());
    if (!name.empty() && name[0] == '_') continue; // _base, _intel_cache, ...

    // A run dir with a job.json but no report.json is attempted-but-incomplete
    // (host killed/crashed before finalizing). Don't drop it (that inflates the
    // numbers); recover its reach from the live events.jsonl -- GuestAgent
    // telemetry is the session-0 service, so it proves OS-up / user-mode (not
    // desktop, same rule as hostChannelBytes>0).
    const auto rpt = entry.path() / "report.json";
    if (!std::filesystem::exists(rpt)) {
      if (!std::filesystem::exists(entry.path() / "job.json")) continue;
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
      } else {
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
