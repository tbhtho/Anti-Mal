#pragma once

// Auto-generate a YARA rule from a scanned sample. The static pipeline already
// extracts everything a useful rule needs (distinctive strings, imphash,
// sha256, PE magic, size); this turns that into a ready-to-tune detection rule
// an analyst can drop into a hunt -- the natural next step after triage/IOC
// export. Pure: a function of (scan, bytes, options) only -- no I/O, no clock,
// deterministic output for a given input.

#include "antimal/Types.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace antimal {

struct YaraGenOptions {
  std::string ruleName;        // "" -> derived from sha256 ("AntiMal_<12hex>")
  size_t maxStrings = 20;      // cap the number of $s strings emitted
  size_t minStringLen = 8;     // shortest candidate string to consider
  size_t maxStringLen = 96;    // longest individual string to emit (truncated)
};

// Build a YARA rule (rule text) from a scan result + the sample's raw bytes.
//
// Strategy:
//   * meta: sha256, imphash (when present), filesize, detected type.
//   * strings: the most distinctive printable ASCII/UTF-16 strings -- long,
//     varied, IOC-bearing (URLs/domains/mutexes ranked first), with common PE
//     boilerplate ("This program cannot be run in DOS mode", import-table DLL
//     names, etc.) filtered out. Each is YARA-escaped and capped in length.
//   * condition: PE magic (uint16(0)==0x5A4D when isPe) AND a filesize bound AND
//     "N of ($s*)" where N scales with how many strings survived.
//
// When no distinctive strings survive, falls back to a magic+filesize+sha256
// rule (a comment notes the sha256 is the only strong anchor). Always returns a
// syntactically complete, single rule.
std::string GenerateYaraRule(const ScanResult &scan,
                             const std::vector<uint8_t> &bytes,
                             const YaraGenOptions &opts = {});

} // namespace antimal
