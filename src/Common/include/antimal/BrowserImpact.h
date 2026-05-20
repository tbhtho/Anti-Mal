#pragma once

#include "antimal/Types.h"

#include <filesystem>
#include <set>
#include <string>
#include <vector>

namespace antimal {

std::string ExtractDomain(std::string_view urlOrHost);
std::set<std::string> NormalizeDomains(const std::vector<std::string> &domains);
std::vector<BrowserRisk> AnalyzeBrowserImpact(const std::vector<std::string> &contactedDomains,
                                              bool decryptBrowserSecrets);
std::vector<BrowserRisk> AnalyzeBrowserImpactFromSyntheticData(
    const std::vector<std::string> &contactedDomains,
    const std::vector<BrowserRisk> &browserRecords);

} // namespace antimal
