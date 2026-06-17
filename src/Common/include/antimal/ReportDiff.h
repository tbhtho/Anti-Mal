#pragma once

#include "antimal/Types.h"

#include <string>
#include <vector>

namespace antimal {

// A structural diff of two analysis reports (T78). Answers "what changed?"
// between two runs — the same sample detonated twice (a determinism / stability
// check) or two related samples / variants (paired with the `similarity`
// command). Pure + deterministic; all lists are sorted and de-duplicated.
struct ReportDiff {
  bool sandboxVerdictChanged = false;
  Verdict oldSandboxVerdict = Verdict::Clean;
  Verdict newSandboxVerdict = Verdict::Clean;
  bool scannerVerdictChanged = false;
  Verdict oldScannerVerdict = Verdict::Clean;
  Verdict newScannerVerdict = Verdict::Clean;
  int oldScannerScore = 0;
  int newScannerScore = 0;

  std::vector<std::string> addedIocs;       // present in B, not A
  std::vector<std::string> removedIocs;     // present in A, not B
  std::vector<std::string> addedFindings;   // finding rule IDs new in B
  std::vector<std::string> removedFindings; // finding rule IDs gone in B
  std::vector<std::string> addedMitre;
  std::vector<std::string> removedMitre;
  std::vector<std::string> addedTags;
  std::vector<std::string> removedTags;

  int oldEventCount = 0;
  int newEventCount = 0;

  // True when nothing material differs (verdicts, scores, and all sets equal).
  bool Identical() const;
};

// Diff report `a` (baseline / "old") against report `b` ("new").
ReportDiff DiffReports(const AnalysisReport &a, const AnalysisReport &b);

// Human-readable one-screen summary of a diff (for the CLI).
std::string FormatReportDiff(const ReportDiff &diff);

} // namespace antimal
