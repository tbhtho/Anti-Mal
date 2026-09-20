#pragma once

// Canonical dynamic-first analysis policy (see the private development documentation).
//
// Antimal is an interactive dynamic-analysis environment. Deep static
// enrichment is LOCKED by default: recursive heuristic scanning, YARA/capa-like
// enrichment, entropy/import scoring, threat-intelligence lookups, and sample
// uploads must not run during agent initialization, as a hidden prerequisite to
// VM analysis, or as a static-only substitute for a requested dynamic
// investigation.
//
// This record is the ONLY way deep static work is allowed. It must come from an
// explicit OPERATOR request, scoped to one file/package/run, and recorded
// (who/mechanism/when). The model cannot authorize itself: an `authorizedBy`
// value that names a model/assistant is refused. An unlock never silently
// persists into unrelated jobs -- it is passed per invocation, never written to
// config.
//
// Basic read-only inventory and identity (path, size, hashes, file/container
// type, package ancestry, bounded architecture/signature metadata) stays
// available at all times; it is preparation, not a malware verdict.

#include <string>

namespace antimal {

struct StaticUnlock {
  bool unlocked = false;
  std::string scope;         // path/package/run the unlock applies to
  std::string authorizedBy;  // "cli-operator" etc. -- never "assistant"/"model"
  std::string mechanism;     // e.g. "cli:--unlock-static"
  std::string recordedAt;    // ISO-8601 timestamp

  // True when this unlock is a valid operator authorization covering `target`.
  bool AppliesTo(const std::string &target) const;
};

// Normalizes a path/scope for comparison (lowercase, forward slashes).
std::string NormalizeStaticScope(const std::string &path);

// The single default-locked evaluation every entry point uses. When it returns
// false, `reason` explains why (empty-scope unlock, scope mismatch, or the
// default lock) and the caller must NOT run deep static enrichment.
bool DeepStaticAllowed(const StaticUnlock &unlock, const std::string &target,
                       std::string *reason);

// Canonical user-visible strings.
const char *StaticAnalysisLockedLabel();   // "Not run - locked"
const char *StaticAnalysisLockedSummary();

} // namespace antimal
