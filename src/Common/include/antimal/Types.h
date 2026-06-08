#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "antimal/PeParser.h" // PeSection (reported in ScanResult)

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
  Unknown, // ran but inconclusive, or sample never executed (gated/healthcheck)
  Error,   // the run itself failed (VM crash, boot failure, host exception)
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
  std::string detectedType; // magic-byte file type ("pe","pdf","zip",...); "" if unknown
  std::string sha1;    // triage cross-reference hash (identification only)
  std::string md5;     // triage cross-reference hash (identification only)
  std::string imphash; // pefile-compatible import hash; empty for non-PE / no imports
  double entropy = 0.0;
  bool isPe = false;
  bool authenticodeSigned = false;
  uint32_t peTimestamp = 0;          // PE compile timestamp (unix epoch secs)
  std::vector<PeSection> peSections; // section table + per-section entropy
  uint64_t peOverlaySize = 0;        // bytes appended after the last section
  double peOverlayEntropy = 0.0;     // entropy of that overlay region
  int embeddedExecutables = 0;       // count of PE images embedded past offset 0
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
  uint64_t kdPacketsReceived = 0;
  uint64_t kdControlPacketsReceived = 0;
  uint64_t kdDataPacketsReceived = 0;
  uint64_t kdAckPacketsSent = 0;
  uint64_t kdResendPacketsSent = 0;
  uint64_t kdResetPacketsReceived = 0;
  uint64_t kdResetPacketsSent = 0;
  uint64_t kdCom1RxQueuedBytes = 0;
  uint64_t kdTargetAcksReceived = 0;
  uint64_t kdDebugPrintBytes = 0;
  uint64_t kdDebugPrintPackets = 0;
  uint64_t kdStateChangePackets = 0;
  uint64_t kdLoadSymbolPackets = 0;
  uint64_t kdStatusPackets = 0;
  uint64_t kdAutoContinuesSent = 0;
  uint64_t kdChecksumFailures = 0;
  uint64_t kdTrailingByteFailures = 0;
  uint32_t kdLastPacketType = 0;
  uint32_t kdLastApiNumber = 0;
  uint32_t kdLastStatus = 0;
  std::string kdLastStatusText;
  std::string kdCom1Status;
  uint64_t com1RegisterReads = 0;
  uint64_t com1RegisterWrites = 0;
  uint64_t com1DataReads = 0;
  uint64_t com1DataWrites = 0;
  uint64_t com1RxBytesQueued = 0;
  uint64_t com1RxBytesRead = 0;
  uint64_t com1RxBytesCleared = 0;
  uint64_t com1IerWrites = 0;
  uint64_t com1FcrWrites = 0;
  uint64_t com1LcrWrites = 0;
  uint64_t com1McrWrites = 0;
  uint64_t com1DllWrites = 0;
  uint64_t com1DlmWrites = 0;
  uint64_t com1IirReads = 0;
  uint64_t com1LsrReads = 0;
  uint32_t com1Ier = 0;
  uint32_t com1Fcr = 0;
  uint32_t com1Lcr = 0;
  uint32_t com1Mcr = 0;
  uint32_t com1Dll = 0;
  uint32_t com1Dlm = 0;
  bool com1Dlab = false;
  bool com1RxInterruptEnabled = false;
  bool com1RxDataReady = false;
  std::string com1TouchStatus;
  uint64_t tpmCrbReads = 0;
  uint64_t tpmCrbWrites = 0;
  uint64_t tpmCrbCommands = 0;
  uint32_t tpmCrbLastCommand = 0;
  uint32_t tpmCrbLastResponse = 0;
  uint64_t tpmCrbLastReadOffset = 0;
  uint64_t tpmCrbLastWriteOffset = 0;
  std::string tpmCrbCommandSummary;
  std::string tpmPcrExtendTraceSummary;
  std::string tpmPcrFinalBanksSummary;
  std::string acpiTpm2EventLogSummary;
  uint64_t fwCfgSmbiosTableBytesRead = 0;
  uint64_t fwCfgSmbiosAnchorBytesRead = 0;
  uint32_t keyboardScancodesInjected = 0;
  uint64_t ps2StatusReads = 0;
  uint64_t ps2DataReads = 0;
  uint64_t ps2CommandWrites = 0;
  uint64_t ps2DataWrites = 0;
  uint64_t ps2KeyboardBytesQueued = 0;
  uint64_t ps2KeyboardBytesRead = 0;
  uint64_t ps2MouseBytesQueued = 0;
  uint64_t ps2MouseBytesRead = 0;
  bool ps2KeyboardPortEnabled = false;
  bool ps2MousePortEnabled = false;
  bool ps2KeyboardScanningEnabled = false;
  std::string ps2InputStatus;
  bool windowsKernelReadGateReached = false;
  std::string windowsKernelReadGateStatus;
  std::string windowsKernelReadGateEvidence;
  std::string windowsKernelReadGateFirstTarget;
  bool windowsUserModeGateReached = false;
  std::string windowsUserModeGateStatus;
  std::string windowsUserModeGateEvidence;
  std::string windowsUserModeGateFirstTarget;
  std::string bootFailureStatus;
  std::string bootFailureStatusName;
  std::string bootFailureStatusSource;
  std::string bootBlocker;
  std::string bootContractSuspect;
  std::string bootContractSuspectDetails;
  std::string ciPolicyInventory;
  std::string bootstatScalarSummary;
  std::vector<std::string> cpuidDiagnostics;
  std::string bootStage;
  std::vector<std::string> bootMilestones;
  std::vector<std::string> interruptDiagnostics;
  std::filesystem::path serialLogPath;
  std::filesystem::path kdLogPath;
  std::filesystem::path kdPacketsPath;
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
