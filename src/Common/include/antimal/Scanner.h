#pragma once

#include "antimal/StaticPolicy.h" // dynamic-first lock (default: locked)
#include "antimal/Types.h"

#include <chrono>
#include <filesystem>
#include <string>
#include <vector>

namespace antimal {

// Knobs for the enrichment pipeline. Defaults give cheap-and-offline
// behavior (strings/IOC mining + builtin tags) — every external-tool and
// network feature is opt-in.

struct ScannerOptions {
  bool mineIocs = true;
  bool runYara = true;
  bool runCapa = true;
  bool runDie = true;
  bool applyTagger = true;
  std::filesystem::path yaraRulesDir;   // empty → "rules/yara" near exe
  std::filesystem::path tagsRulesPath;  // empty → "rules/tags.json" near exe, else builtin
  bool intelLookupEnabled = false;      // master switch (network access)
  std::string virusTotalApiKey;         // empty → VT skipped
  bool malwareBazaarEnabled = true;     // free, no key
  std::filesystem::path intelCacheDir;  // empty → workspaceRoot/_intel_cache when set elsewhere
  std::chrono::milliseconds intelTimeout{15000};
  // Deep static enrichment runs ONLY when this operator authorization covers the
  // scanned target; the flags above are additionally required but are not
  // sufficient on their own (see the private development documentation).
  StaticUnlock staticUnlock;
};

double CalculateEntropy(const std::vector<uint8_t> &data);

// Magic-byte file-type identification, independent of the file extension. Returns
// a short lowercase label ("pe", "elf", "macho", "pdf", "zip", "ole", "rtf",
// "elf", "script", "lnk", ...) or "" when nothing matches. Used to flag
// extension/content masquerading (e.g. invoice.pdf that is really a PE).
std::string IdentifyFileType(const std::vector<uint8_t> &data);

// Counts PE images embedded at a NON-zero offset (an "MZ" whose e_lfanew points
// at a valid "PE\0\0"). The host file's own header at offset 0 is excluded, so a
// non-zero count means the file carries one or more additional executables --
// the defining trait of a dropper/installer payload. Capped to a sane maximum.
int CountEmbeddedExecutables(const std::vector<uint8_t> &data);

// Maps the import table to coarse behavioral capabilities (anti-debug,
// keylogging, screen capture, clipboard, crypto, process discovery, privilege
// adjustment, runtime API resolution, service control). Pure over the import
// name list (entries shaped "dll!func"), returns one finding per capability
// present. The Any.Run-style "what can this do" row, derived statically.
std::vector<ScanFinding>
DetectImportCapabilities(const std::vector<std::string> &imports);

// Static evidence policy (G1-09/G1-11). A static scan produces two classes of
// signal:
//   * GENERIC leads -- import capabilities, entropy, TLS callbacks, unsigned
//     status, filename mismatch, packer section names. Useful for triage, but
//     they can never accumulate into a categorical malware verdict by
//     arithmetic alone.
//   * HIGH-SPECIFICITY evidence -- a decoded Cobalt Strike config, shellcode
//     stubs, recovered obfuscated C2, a known-malware threat-intel hit. These
//     are the only static findings that can justify Malicious.
// ClassifyStaticEvidence is pure over the finding list so the policy is
// unit-testable without touching the disk.
struct StaticEvidenceClassification {
  int genericScore = 0;  // weak/ambiguous indicators (accumulation capped)
  int specificScore = 0; // high-specificity indicators
  int leadScore = 0;     // strong obfuscation leads (XOR/base64 IOC recovery)
  std::vector<std::string> specificRules; // rule ids that contributed
  std::vector<std::string> leadRules;     // obfuscation-lead rule ids
};
StaticEvidenceClassification
ClassifyStaticEvidence(const std::vector<ScanFinding> &findings);
bool IsHighSpecificityStaticRule(const std::string &ruleId);
// Obfuscation leads (XOR/base64 URL recovery): strong enough to justify
// Suspicious with corroboration, but NOT a Malicious verdict on their own.
bool IsStrongObfuscationLead(const std::string &ruleId);
// Map (total score, classification) to a verdict under the static policy:
// Malicious requires >= 60 of HIGH-SPECIFICITY evidence; generic accumulation
// caps at Suspicious.
Verdict StaticVerdictFromEvidence(int totalScore,
                                  const StaticEvidenceClassification &c);

ScanResult ScanFile(const std::filesystem::path &path);
ScanResult ScanFile(const std::filesystem::path &path,
                    const ScannerOptions &options);

std::vector<ScanResult> ScanPath(const std::filesystem::path &path);
std::vector<ScanResult> ScanPath(const std::filesystem::path &path,
                                 const ScannerOptions &options);

std::string FormatScanText(const ScanResult &result);

} // namespace antimal
