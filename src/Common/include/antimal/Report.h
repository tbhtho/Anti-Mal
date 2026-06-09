#pragma once

#include "antimal/Types.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace antimal {

// One process in the analyst-grade process tree. `depth` is the nesting level
// (roots = 0); the renderer indents by it. The display fields are denormalized
// from the start event (+ the matching stop event for exitCode) so the HTML
// emitter is a dumb projection of this struct.
struct ProcessTreeNode {
  uint32_t processId = 0;
  uint32_t parentProcessId = 0;
  int depth = 0;
  std::string imagePath;       // base image name
  std::string commandLine;     // full command line (may carry a truncation marker)
  std::string integrityLevel;  // "Low" | "Medium" | "High" | "System" | ...
  std::string userName;        // "DOMAIN\\user"
  std::string exitCode;        // hex exit code if the process exited; "" otherwise
  bool exited = false;
};

// Pure: build an ordered, depth-annotated process tree from `process.start`
// events (PID -> children via processId/parentProcessId), then flatten it
// depth-first into the order the report renders. Robust to real-world telemetry:
// missing parents and PIDs whose parent isn't a known process are treated as
// roots; cycles are broken by a visited set and a hard depth cap, so the
// function always terminates and never recurses unboundedly. Output order is
// deterministic (roots and children are visited in ascending PID order).
// `exitCode`/`exited` are filled from the matching `process.stop` event (or a
// start event's `exitCode` detail) when present. Returns an empty vector when
// there are no process.start events.
std::vector<ProcessTreeNode> BuildProcessTree(const std::vector<EventRecord> &events);

std::string HtmlEscape(std::string_view text);
std::string BuildHtmlReport(const AnalysisReport &report);
// Same as BuildHtmlReport but embeds an explicit list of screenshot frames
// (typically discovered from `screenshots/` next to the report). When
// guest-* and diagnostic frames are both present, guest frames are preferred.
// When frames are empty the filmstrip pane shows an "empty" hint.
std::string BuildHtmlReportWithFrames(const AnalysisReport &report,
                                      const std::vector<std::filesystem::path> &frames);
AnalysisReport LoadReportBestEffort(const std::filesystem::path &path);
void WriteReportJson(const std::filesystem::path &path, const AnalysisReport &report);
void WriteReportHtml(const std::filesystem::path &path, const AnalysisReport &report);
std::vector<std::string> ExtractNetworkDomainsFromReportText(std::string_view jsonText);

// Distinct, sorted MITRE ATT&CK technique IDs observed on a detonation run.
// Unions the non-empty EventRecord.mitre values from the dynamic run with the
// capa-derived technique IDs from a static scan (when one is available). Pure;
// invents nothing — only IDs that were actually observed/derived appear.
std::vector<std::string> AggregateMitreTechniques(
    const std::vector<EventRecord> &events, const ScanResult &scan);

// Distinct, sorted hostnames/domains the run actually resolved or addressed by
// name (DNS query names and HTTP Host headers from network EventRecords). The
// current in-guest TCP-table telemetry is IP:port only, so this legitimately
// returns empty until DNS/SNI capture lands — it never fabricates a domain from
// a bare IP.
std::vector<std::string> AggregateNetworkDomains(
    const std::vector<EventRecord> &events);

} // namespace antimal
