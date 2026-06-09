#pragma once

#include "antimal/Types.h"

#include <filesystem>
#include <string>
#include <vector>

namespace antimal {

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
