#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace antimal {

enum class NetworkMode {
  Disabled,
  HostOnly,
  Nat,
};

enum class Verdict {
  Clean,
  Suspicious,
  Malicious,
  Error,
};

struct EventRecord {
  std::string timestampUtc;
  std::string source;
  std::string category;
  std::string action;
  uint32_t processId = 0;
  uint32_t parentProcessId = 0;
  std::string imagePath;
  std::string target;
  std::map<std::string, std::string> details;
  std::string mitre;
};

struct JobConfig {
  int schemaVersion = 1;
  std::string runId;
  std::filesystem::path samplePath;
  std::vector<std::string> arguments;
  uint32_t timeoutMs = 180000;
  NetworkMode networkMode = NetworkMode::Disabled;
  bool collectScreenshots = false;
  std::filesystem::path outputDir;
};

struct ScanFinding {
  std::string ruleId;
  std::string message;
  int score = 0;
};

// Enrichment payloads attached to a scan result. Defined here (rather
// than included from the enrichment headers) so Types.h stays the single
// place that documents the shape of an AntiMal record. The enrichment
// headers (Strings.h, ExternalTools.h, etc.) own the producers.
struct ScanTag {
  std::string tag;        // "stealer", "packed", ...
  std::string category;   // "family" | "capability" | "packer" | "language"
  int confidence = 0;     // 0..100
  std::vector<std::string> reasons; // human-readable
};

struct ScanIntelHit {
  std::string source;     // "malwarebazaar" | "virustotal"
  bool known = false;
  std::string family;
  std::vector<std::string> tags;
  int detectionRatio = 0;
  int totalScanners = 0;
  std::string firstSeen;
  std::string lastSeen;
  std::string permalink;
  std::string error;
};

struct ScanIocSet {
  std::vector<std::string> urls;
  std::vector<std::string> ips;
  std::vector<std::string> domains;
  std::vector<std::string> registryPaths;
  std::vector<std::string> filePaths;
  std::vector<std::string> mutexHints;
  std::vector<std::string> base64Blobs;
  std::vector<std::string> suspiciousApis;
};

struct ScanYaraMatch {
  std::string ruleName;
  std::string ruleNamespace;
  std::vector<std::string> tags;
  std::vector<std::string> meta;
};

struct ScanCapaCapability {
  std::string name;
  std::vector<std::string> mitreTechniques;
  std::vector<std::string> mbcBehaviors;
  std::string ruleNamespace;
};

struct ScanDieDetection {
  std::string type;
  std::string name;
  std::string version;
  std::string options;
};

struct ScanResult {
  std::filesystem::path path;
  std::string sha256;
  double entropy = 0.0;
  bool isPe = false;
  bool authenticodeSigned = false;
  std::vector<std::string> imports;
  std::vector<ScanFinding> findings;
  int score = 0;
  Verdict verdict = Verdict::Clean;

  // Enrichment outputs. Empty when the corresponding analyzer was
  // disabled or not available on this host.
  ScanIocSet iocs;
  std::vector<ScanTag> tags;
  std::vector<ScanYaraMatch> yaraMatches;
  std::vector<ScanCapaCapability> capaCapabilities;
  std::vector<ScanDieDetection> dieDetections;
  std::vector<ScanIntelHit> intelHits;
};

struct BrowserRisk {
  std::string site;
  std::string domain;
  bool contactedBySample = false;
  bool savedCredentials = false;
  bool cookiesPresent = false;
  bool decryptedEvidenceAvailable = false;
  std::string lastVisited;
  std::string recommendation;
};

struct DynamicRunSummary {
  bool started = false;
  bool completed = false;
  bool timedOut = false;
  bool crashed = false;
  bool sampleExecuted = false;
  bool firmwareIdle = false;
  bool guestAgentConnected = false;
  std::string status;
  NetworkMode networkMode = NetworkMode::Disabled;
  uint32_t framesCaptured = 0;
  uint32_t eventsCaptured = 0;
  uint32_t artifactsCaptured = 0;
  uint32_t vcpuExits = 0;
  uint32_t hltCount = 0;
  uint32_t ideCommandsIssued = 0;
  uint32_t ideIdentifyCommands = 0;
  uint32_t ideReadCommands = 0;
  uint32_t ideWriteCommands = 0;
  uint32_t ideAbortedCommands = 0;
  uint64_t ideSectorsRead = 0;
  uint64_t ideSectorsWritten = 0;
  bool ideSawRead = false;
  bool ideSawWrite = false;
  uint64_t ideMinReadLba = 0;
  uint64_t ideMaxReadEndLba = 0;
  uint64_t ideMinWriteLba = 0;
  uint64_t ideMaxWriteEndLba = 0;
  uint32_t unhandledIo = 0;
  uint32_t unhandledMmio = 0;
  uint32_t watchdogCancellations = 0;
  uint32_t ideInterruptsRequested = 0;
  uint32_t ideInterruptsInjected = 0;
  uint32_t ideInterruptsFailed = 0;
  uint32_t ideInterruptsPending = 0;
  uint32_t ideInterruptsIoApic = 0;
  uint32_t ideInterruptsPicFallback = 0;
  uint32_t pitInterruptsPending = 0;
  uint32_t rtcInterruptsPending = 0;
  uint32_t irqIoApicDeliveries = 0;
  uint32_t irqPicFallbackDeliveries = 0;
  uint32_t irqDeliveryFailures = 0;
  uint32_t masterPicVectorBase = 0;
  uint32_t slavePicVectorBase = 0;
  uint32_t masterPicMask = 0xFF;
  uint32_t slavePicMask = 0xFF;
  bool pm1SleepEnable = false;
  bool pm1HostStopRequested = false;
  uint32_t pm1SleepType = 0;
  uint32_t pm1ControlValue = 0;
  uint64_t pm1SleepRequests = 0;
  std::vector<std::string> bootMilestones;
  std::vector<std::string> interruptDiagnostics;
  std::filesystem::path serialLogPath;
  std::filesystem::path vmSummaryPath;
};

struct AnalysisReport {
  int schemaVersion = 1;
  std::string runId;
  std::filesystem::path samplePath;
  ScanResult scannerVerdict;
  Verdict sandboxVerdict = Verdict::Clean;
  DynamicRunSummary dynamicSummary;
  std::vector<EventRecord> events;
  std::vector<std::string> mitreTechniques;
  std::vector<std::filesystem::path> artifacts;
  std::vector<std::string> networkDomains;
  std::vector<BrowserRisk> browserImpact;
  std::vector<std::string> errors;
};

std::string ToString(NetworkMode mode);
std::optional<NetworkMode> ParseNetworkMode(std::string value);
std::string ToString(Verdict verdict);
Verdict VerdictFromScore(int score);

} // namespace antimal
