#include "antimal/EventTime.h"

#include <cstdio>

namespace antimal {
namespace {

// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm). Valid for
// any Gregorian date; no <ctime>/timezone dependency.
int64_t DaysFromCivil(int64_t y, unsigned m, unsigned d) {
  y -= m <= 2;
  const int64_t era = (y >= 0 ? y : y - 399) / 400;
  const unsigned yoe = static_cast<unsigned>(y - era * 400);
  const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

} // namespace

int64_t ParseIso8601ToEpochSeconds(const std::string &iso) {
  int y = 0, mo = 0, d = 0, h = 0, mi = 0, s = 0;
  // Tolerates a trailing 'Z', '.fff', or offset — we only read the leading 6.
  if (std::sscanf(iso.c_str(), "%d-%d-%dT%d:%d:%d", &y, &mo, &d, &h, &mi, &s) != 6) {
    return -1;
  }
  if (mo < 1 || mo > 12 || d < 1 || d > 31 || h < 0 || h > 23 || mi < 0 ||
      mi > 59 || s < 0 || s > 60) {
    return -1;
  }
  const int64_t days = DaysFromCivil(y, static_cast<unsigned>(mo),
                                     static_cast<unsigned>(d));
  return days * 86400 + h * 3600 + mi * 60 + s;
}

std::string RelativeTimeLabel(int64_t epochSeconds, int64_t anchorEpochSeconds) {
  if (epochSeconds < 0 || anchorEpochSeconds < 0) return "";
  int64_t diff = epochSeconds - anchorEpochSeconds;
  const char *sign = diff < 0 ? "T-" : "T+";
  if (diff < 0) diff = -diff;
  char buf[32];
  if (diff >= 60) {
    std::snprintf(buf, sizeof(buf), "%s%lldm%02llds", sign,
                  static_cast<long long>(diff / 60),
                  static_cast<long long>(diff % 60));
  } else {
    std::snprintf(buf, sizeof(buf), "%s%llds", sign,
                  static_cast<long long>(diff));
  }
  return std::string(buf);
}

} // namespace antimal
