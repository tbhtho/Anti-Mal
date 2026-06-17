#pragma once

#include <cstdint>
#include <string>

namespace antimal {

// Parse an ISO-8601 UTC timestamp ("YYYY-MM-DDTHH:MM:SS", optional fractional
// seconds and trailing 'Z') to a Unix epoch in seconds. Returns -1 on a parse
// failure or an out-of-range field. Timezone is assumed UTC (the event journal
// writes UTC). Pure; used to give the report timeline normalized relative offsets.
int64_t ParseIso8601ToEpochSeconds(const std::string &iso);

// A compact "T+1m02s" / "T+8s" / "T-3s" label for an event epoch relative to the
// run anchor (the earliest event). Returns "" when either epoch is unknown (-1).
std::string RelativeTimeLabel(int64_t epochSeconds, int64_t anchorEpochSeconds);

} // namespace antimal
