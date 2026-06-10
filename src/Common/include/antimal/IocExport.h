#pragma once

// Machine-readable IOC export (backlog T79). Given a finished AnalysisReport,
// gather its indicators (hashes, network endpoints, registry persistence,
// mutexes, URLs, MITRE techniques) and emit them in formats a SOC / analyst can
// ingest directly: STIX 2.1 bundle, MISP event, and flat CSV.
//
// The exporters are PURE (report in -> string out): no file I/O, no clock, no
// randomness. STIX object ids are derived deterministically from the indicator
// content (a SHA-256-seeded UUID) so the same report always produces byte-for-
// byte identical output -- the unit tests round-trip-parse the result. All
// values originate from analyzed malware, so everything is escaped on the way
// out; a hostile value can never break out of the JSON or CSV framing.

#include "antimal/Types.h"

#include <string>
#include <vector>

namespace antimal {

// A single normalized indicator gathered from a report. `type` is the IOC
// kind ("sha256", "md5", "sha1", "domain", "ipv4", "url", "regkey", "mutex",
// "mitre"); `value` is the indicator; `context` is a short human-readable
// provenance note used for the CSV context column and the SDO description.
struct IocIndicator {
  std::string type;
  std::string value;
  std::string context;
};

// De-duplicated, deterministically-ordered indicator set pulled from a report.
// Order is grouped by type then first-seen, so two equal reports collect the
// same list. Exposed mainly so tests (and future consumers) can inspect what
// was gathered independently of a particular output format.
std::vector<IocIndicator> CollectIndicators(const AnalysisReport &report);

// STIX 2.1 bundle: a `report` SDO plus `indicator` / `attack-pattern` SDOs.
std::string ExportIocsStix(const AnalysisReport &report);

// MISP event JSON: {"Event": {"info", "Attribute":[...], "Tag":[...]}}.
std::string ExportIocsMisp(const AnalysisReport &report);

// Flat CSV (RFC 4180): header row + one `type,value,context` row per indicator.
std::string ExportIocsCsv(const AnalysisReport &report);

} // namespace antimal
