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
// frames are empty the filmstrip pane shows an "empty" hint.
std::string BuildHtmlReportWithFrames(const AnalysisReport &report,
                                      const std::vector<std::filesystem::path> &frames);
AnalysisReport LoadReportBestEffort(const std::filesystem::path &path);
void WriteReportJson(const std::filesystem::path &path, const AnalysisReport &report);
void WriteReportHtml(const std::filesystem::path &path, const AnalysisReport &report);
std::vector<std::string> ExtractNetworkDomainsFromReportText(std::string_view jsonText);

} // namespace antimal
