#pragma once

#include "antimal/Types.h"

#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace antimal {

std::string JsonEscape(std::string_view text);
std::string JsonQuote(std::string_view text);
std::string ToJson(const JobConfig &job);
std::string ToJson(const DynamicRunSummary &summary);
std::string ToJson(const ScanResult &scan);
std::string ToJson(const AnalysisReport &report);

class JsonObjectBuilder {
public:
  void AddString(std::string_view key, std::string_view value);
  void AddNumber(std::string_view key, int64_t value);
  void AddDouble(std::string_view key, double value);
  void AddBool(std::string_view key, bool value);
  void AddRaw(std::string_view key, std::string value);
  std::string Finish() const;

private:
  std::vector<std::string> entries_;
};

} // namespace antimal
