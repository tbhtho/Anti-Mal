#pragma once

#include "antimal/Types.h"

#include <filesystem>

namespace antimal {

JobConfig LoadJobBestEffort(const std::filesystem::path &path);
AnalysisReport RunGuestJob(const JobConfig &job);

} // namespace antimal
