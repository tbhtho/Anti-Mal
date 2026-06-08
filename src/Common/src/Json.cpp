#include "antimal/Json.h"

#include "antimal/FileUtil.h"

#include <iomanip>
#include <set>

namespace antimal {

std::string ToString(NetworkMode mode) {
  switch (mode) {
  case NetworkMode::Disabled:
    return "disabled";
  case NetworkMode::HostOnly:
    return "hostonly";
  case NetworkMode::Nat:
    return "nat";
  }
  return "disabled";
}

std::optional<NetworkMode> ParseNetworkMode(std::string value) {
  value = ToLowerAscii(Trim(value));
  if (value == "disabled" || value == "off") {
    return NetworkMode::Disabled;
  }
  if (value == "hostonly" || value == "host-only" || value == "simulated") {
    return NetworkMode::HostOnly;
  }
  if (value == "nat" || value == "enabled") {
    return NetworkMode::Nat;
  }
  return std::nullopt;
}

std::string ToString(Verdict verdict) {
  switch (verdict) {
  case Verdict::Clean:
    return "clean";
  case Verdict::Suspicious:
    return "suspicious";
  case Verdict::Malicious:
    return "malicious";
  case Verdict::Unknown:
    return "unknown";
  case Verdict::Error:
    return "error";
  }
  return "error";
}

Verdict VerdictFromScore(int score) {
  if (score >= 85) {
    return Verdict::Malicious;
  }
  if (score >= 50) {
    return Verdict::Suspicious;
  }
  return Verdict::Clean;
}

std::string JsonEscape(std::string_view text) {
  std::ostringstream out;
  for (unsigned char c : text) {
    switch (c) {
    case '\\':
      out << "\\\\";
      break;
    case '"':
      out << "\\\"";
      break;
    case '\b':
      out << "\\b";
      break;
    case '\f':
      out << "\\f";
      break;
    case '\n':
      out << "\\n";
      break;
    case '\r':
      out << "\\r";
      break;
    case '\t':
      out << "\\t";
      break;
    default:
      if (c < 0x20) {
        out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
            << static_cast<int>(c);
      } else {
        out << static_cast<char>(c);
      }
      break;
    }
  }
  return out.str();
}

std::string JsonQuote(std::string_view text) {
  return "\"" + JsonEscape(text) + "\"";
}

void JsonObjectBuilder::AddString(std::string_view key, std::string_view value) {
  entries_.push_back(JsonQuote(key) + ":" + JsonQuote(value));
}

void JsonObjectBuilder::AddNumber(std::string_view key, int64_t value) {
  entries_.push_back(JsonQuote(key) + ":" + std::to_string(value));
}

void JsonObjectBuilder::AddDouble(std::string_view key, double value) {
  std::ostringstream out;
  out << std::fixed << std::setprecision(4) << value;
  entries_.push_back(JsonQuote(key) + ":" + out.str());
}

void JsonObjectBuilder::AddBool(std::string_view key, bool value) {
  entries_.push_back(JsonQuote(key) + ":" + (value ? "true" : "false"));
}

void JsonObjectBuilder::AddRaw(std::string_view key, std::string value) {
  entries_.push_back(JsonQuote(key) + ":" + std::move(value));
}

std::string JsonObjectBuilder::Finish() const {
  std::ostringstream out;
  out << "{";
  for (size_t i = 0; i < entries_.size(); ++i) {
    if (i) {
      out << ",";
    }
    out << entries_[i];
  }
  out << "}";
  return out.str();
}

static std::string JsonStringArray(const std::vector<std::string> &items) {
  std::ostringstream out;
  out << "[";
  for (size_t i = 0; i < items.size(); ++i) {
    if (i) {
      out << ",";
    }
    out << JsonQuote(items[i]);
  }
  out << "]";
  return out.str();
}

static std::string JsonPathArray(const std::vector<std::filesystem::path> &items) {
  std::ostringstream out;
  out << "[";
  for (size_t i = 0; i < items.size(); ++i) {
    if (i) {
      out << ",";
    }
    out << JsonQuote(PathToUtf8(items[i]));
  }
  out << "]";
  return out.str();
}

std::string ToJson(const JobConfig &job) {
  JsonObjectBuilder obj;
  obj.AddNumber("schemaVersion", job.schemaVersion);
  obj.AddString("runId", job.runId);
  obj.AddString("samplePath", PathToUtf8(job.samplePath));
  obj.AddRaw("arguments", JsonStringArray(job.arguments));
  obj.AddNumber("timeoutMs", job.timeoutMs);
  obj.AddString("networkMode", ToString(job.networkMode));
  obj.AddBool("collectScreenshots", job.collectScreenshots);
  obj.AddString("outputDir", PathToUtf8(job.outputDir));
  return obj.Finish();
}

std::string ToJson(const DynamicRunSummary &summary) {
  JsonObjectBuilder obj;
  obj.AddBool("started", summary.started);
  obj.AddBool("completed", summary.completed);
  obj.AddBool("timedOut", summary.timedOut);
  obj.AddBool("crashed", summary.crashed);
  obj.AddBool("sampleExecuted", summary.sampleExecuted);
  obj.AddBool("firmwareIdle", summary.firmwareIdle);
  obj.AddBool("guestAgentConnected", summary.guestAgentConnected);
  obj.AddString("status", summary.status);
  obj.AddString("networkMode", ToString(summary.networkMode));
  obj.AddNumber("framesCaptured", summary.framesCaptured);
  obj.AddNumber("eventsCaptured", summary.eventsCaptured);
  obj.AddNumber("artifactsCaptured", summary.artifactsCaptured);
  obj.AddNumber("vcpuExits", summary.vcpuExits);
  obj.AddNumber("hltCount", summary.hltCount);
  obj.AddNumber("ideCommandsIssued", summary.ideCommandsIssued);
  obj.AddNumber("ideIdentifyCommands", summary.ideIdentifyCommands);
  obj.AddNumber("ideReadCommands", summary.ideReadCommands);
  obj.AddNumber("ideWriteCommands", summary.ideWriteCommands);
  obj.AddNumber("ideAbortedCommands", summary.ideAbortedCommands);
  obj.AddNumber("ideSectorsRead", summary.ideSectorsRead);
  obj.AddNumber("ideSectorsWritten", summary.ideSectorsWritten);
  obj.AddBool("ideSawRead", summary.ideSawRead);
  obj.AddBool("ideSawWrite", summary.ideSawWrite);
  obj.AddNumber("ideMinReadLba", summary.ideMinReadLba);
  obj.AddNumber("ideMaxReadEndLba", summary.ideMaxReadEndLba);
  obj.AddNumber("ideMinWriteLba", summary.ideMinWriteLba);
  obj.AddNumber("ideMaxWriteEndLba", summary.ideMaxWriteEndLba);
  obj.AddNumber("unhandledIo", summary.unhandledIo);
  obj.AddNumber("unhandledMmio", summary.unhandledMmio);
  obj.AddNumber("watchdogCancellations", summary.watchdogCancellations);
  obj.AddNumber("ideInterruptsRequested", summary.ideInterruptsRequested);
  obj.AddNumber("ideInterruptsInjected", summary.ideInterruptsInjected);
  obj.AddNumber("ideInterruptsFailed", summary.ideInterruptsFailed);
  obj.AddNumber("ideInterruptsPending", summary.ideInterruptsPending);
  obj.AddNumber("ideInterruptsIoApic", summary.ideInterruptsIoApic);
  obj.AddNumber("ideInterruptsPicFallback",
                summary.ideInterruptsPicFallback);
  obj.AddNumber("pitInterruptsPending", summary.pitInterruptsPending);
  obj.AddNumber("rtcInterruptsPending", summary.rtcInterruptsPending);
  obj.AddNumber("irqIoApicDeliveries", summary.irqIoApicDeliveries);
  obj.AddNumber("irqPicFallbackDeliveries",
                summary.irqPicFallbackDeliveries);
  obj.AddNumber("irqDeliveryFailures", summary.irqDeliveryFailures);
  obj.AddNumber("masterPicVectorBase", summary.masterPicVectorBase);
  obj.AddNumber("slavePicVectorBase", summary.slavePicVectorBase);
  obj.AddNumber("masterPicMask", summary.masterPicMask);
  obj.AddNumber("slavePicMask", summary.slavePicMask);
  obj.AddBool("pm1SleepEnable", summary.pm1SleepEnable);
  obj.AddBool("pm1HostStopRequested", summary.pm1HostStopRequested);
  obj.AddNumber("pm1SleepType", summary.pm1SleepType);
  obj.AddNumber("pm1ControlValue", summary.pm1ControlValue);
  obj.AddNumber("pm1SleepRequests", summary.pm1SleepRequests);
  obj.AddNumber("kdPacketsReceived", summary.kdPacketsReceived);
  obj.AddNumber("kdControlPacketsReceived",
                summary.kdControlPacketsReceived);
  obj.AddNumber("kdDataPacketsReceived", summary.kdDataPacketsReceived);
  obj.AddNumber("kdAckPacketsSent", summary.kdAckPacketsSent);
  obj.AddNumber("kdResendPacketsSent", summary.kdResendPacketsSent);
  obj.AddNumber("kdResetPacketsReceived", summary.kdResetPacketsReceived);
  obj.AddNumber("kdResetPacketsSent", summary.kdResetPacketsSent);
  obj.AddNumber("kdCom1RxQueuedBytes", summary.kdCom1RxQueuedBytes);
  obj.AddNumber("kdTargetAcksReceived", summary.kdTargetAcksReceived);
  obj.AddNumber("kdDebugPrintBytes", summary.kdDebugPrintBytes);
  obj.AddNumber("kdDebugPrintPackets", summary.kdDebugPrintPackets);
  obj.AddNumber("kdStateChangePackets", summary.kdStateChangePackets);
  obj.AddNumber("kdLoadSymbolPackets", summary.kdLoadSymbolPackets);
  obj.AddNumber("kdStatusPackets", summary.kdStatusPackets);
  obj.AddNumber("kdAutoContinuesSent", summary.kdAutoContinuesSent);
  obj.AddNumber("kdChecksumFailures", summary.kdChecksumFailures);
  obj.AddNumber("kdTrailingByteFailures", summary.kdTrailingByteFailures);
  obj.AddNumber("kdLastPacketType", summary.kdLastPacketType);
  obj.AddNumber("kdLastApiNumber", summary.kdLastApiNumber);
  obj.AddNumber("kdLastStatus", summary.kdLastStatus);
  obj.AddString("kdLastStatusText", summary.kdLastStatusText);
  obj.AddString("kdCom1Status", summary.kdCom1Status);
  obj.AddNumber("com1RegisterReads", summary.com1RegisterReads);
  obj.AddNumber("com1RegisterWrites", summary.com1RegisterWrites);
  obj.AddNumber("com1DataReads", summary.com1DataReads);
  obj.AddNumber("com1DataWrites", summary.com1DataWrites);
  obj.AddNumber("com1RxBytesQueued", summary.com1RxBytesQueued);
  obj.AddNumber("com1RxBytesRead", summary.com1RxBytesRead);
  obj.AddNumber("com1RxBytesCleared", summary.com1RxBytesCleared);
  obj.AddNumber("com1IerWrites", summary.com1IerWrites);
  obj.AddNumber("com1FcrWrites", summary.com1FcrWrites);
  obj.AddNumber("com1LcrWrites", summary.com1LcrWrites);
  obj.AddNumber("com1McrWrites", summary.com1McrWrites);
  obj.AddNumber("com1DllWrites", summary.com1DllWrites);
  obj.AddNumber("com1DlmWrites", summary.com1DlmWrites);
  obj.AddNumber("com1IirReads", summary.com1IirReads);
  obj.AddNumber("com1LsrReads", summary.com1LsrReads);
  obj.AddNumber("com1Ier", summary.com1Ier);
  obj.AddNumber("com1Fcr", summary.com1Fcr);
  obj.AddNumber("com1Lcr", summary.com1Lcr);
  obj.AddNumber("com1Mcr", summary.com1Mcr);
  obj.AddNumber("com1Dll", summary.com1Dll);
  obj.AddNumber("com1Dlm", summary.com1Dlm);
  obj.AddBool("com1Dlab", summary.com1Dlab);
  obj.AddBool("com1RxInterruptEnabled", summary.com1RxInterruptEnabled);
  obj.AddBool("com1RxDataReady", summary.com1RxDataReady);
  obj.AddString("com1TouchStatus", summary.com1TouchStatus);
  obj.AddNumber("tpmCrbReads", summary.tpmCrbReads);
  obj.AddNumber("tpmCrbWrites", summary.tpmCrbWrites);
  obj.AddNumber("tpmCrbCommands", summary.tpmCrbCommands);
  obj.AddNumber("tpmCrbLastCommand", summary.tpmCrbLastCommand);
  obj.AddNumber("tpmCrbLastResponse", summary.tpmCrbLastResponse);
  obj.AddNumber("tpmCrbLastReadOffset", summary.tpmCrbLastReadOffset);
  obj.AddNumber("tpmCrbLastWriteOffset", summary.tpmCrbLastWriteOffset);
  obj.AddString("tpmCrbCommandSummary", summary.tpmCrbCommandSummary);
  obj.AddString("tpmPcrExtendTraceSummary",
                summary.tpmPcrExtendTraceSummary);
  obj.AddString("tpmPcrFinalBanksSummary",
                summary.tpmPcrFinalBanksSummary);
  obj.AddString("acpiTpm2EventLogSummary",
                summary.acpiTpm2EventLogSummary);
  obj.AddNumber("fwCfgSmbiosTableBytesRead",
                summary.fwCfgSmbiosTableBytesRead);
  obj.AddNumber("fwCfgSmbiosAnchorBytesRead",
                summary.fwCfgSmbiosAnchorBytesRead);
  obj.AddNumber("keyboardScancodesInjected",
                summary.keyboardScancodesInjected);
  obj.AddNumber("ps2StatusReads", summary.ps2StatusReads);
  obj.AddNumber("ps2DataReads", summary.ps2DataReads);
  obj.AddNumber("ps2CommandWrites", summary.ps2CommandWrites);
  obj.AddNumber("ps2DataWrites", summary.ps2DataWrites);
  obj.AddNumber("ps2KeyboardBytesQueued",
                summary.ps2KeyboardBytesQueued);
  obj.AddNumber("ps2KeyboardBytesRead", summary.ps2KeyboardBytesRead);
  obj.AddNumber("ps2MouseBytesQueued", summary.ps2MouseBytesQueued);
  obj.AddNumber("ps2MouseBytesRead", summary.ps2MouseBytesRead);
  obj.AddBool("ps2KeyboardPortEnabled",
              summary.ps2KeyboardPortEnabled);
  obj.AddBool("ps2MousePortEnabled", summary.ps2MousePortEnabled);
  obj.AddBool("ps2KeyboardScanningEnabled",
              summary.ps2KeyboardScanningEnabled);
  obj.AddString("ps2InputStatus", summary.ps2InputStatus);
  obj.AddBool("windowsKernelReadGateReached",
              summary.windowsKernelReadGateReached);
  obj.AddString("windowsKernelReadGateStatus",
                summary.windowsKernelReadGateStatus);
  obj.AddString("windowsKernelReadGateEvidence",
                summary.windowsKernelReadGateEvidence);
  obj.AddString("windowsKernelReadGateFirstTarget",
                summary.windowsKernelReadGateFirstTarget);
  obj.AddString("kernelReadGate", summary.windowsKernelReadGateStatus);
  obj.AddBool("windowsUserModeGateReached",
              summary.windowsUserModeGateReached);
  obj.AddString("windowsUserModeGateStatus",
                summary.windowsUserModeGateStatus);
  obj.AddString("windowsUserModeGateEvidence",
                summary.windowsUserModeGateEvidence);
  obj.AddString("windowsUserModeGateFirstTarget",
                summary.windowsUserModeGateFirstTarget);
  obj.AddString("userModeGate", summary.windowsUserModeGateStatus);
  obj.AddString("firstUserModeTarget",
                summary.windowsUserModeGateFirstTarget);
  obj.AddString("bootFailureStatus", summary.bootFailureStatus);
  obj.AddString("bootFailureStatusName", summary.bootFailureStatusName);
  obj.AddString("bootFailureStatusSource", summary.bootFailureStatusSource);
  obj.AddString("bootBlocker", summary.bootBlocker);
  obj.AddString("bootContractSuspect", summary.bootContractSuspect);
  obj.AddString("bootContractSuspectDetails",
                summary.bootContractSuspectDetails);
  obj.AddString("ciPolicyInventory", summary.ciPolicyInventory);
  obj.AddString("bootstatScalarSummary", summary.bootstatScalarSummary);
  obj.AddRaw("cpuidDiagnostics", JsonStringArray(summary.cpuidDiagnostics));
  obj.AddString("bootStage", summary.bootStage);
  obj.AddRaw("bootMilestones", JsonStringArray(summary.bootMilestones));
  obj.AddRaw("interruptDiagnostics",
             JsonStringArray(summary.interruptDiagnostics));
  obj.AddString("serialLogPath", PathToUtf8(summary.serialLogPath));
  obj.AddString("kdLogPath", PathToUtf8(summary.kdLogPath));
  obj.AddString("kdPacketsPath", PathToUtf8(summary.kdPacketsPath));
  obj.AddString("vmSummaryPath", PathToUtf8(summary.vmSummaryPath));
  return obj.Finish();
}

static std::string IocsToJson(const ScanIocSet &iocs) {
  JsonObjectBuilder obj;
  obj.AddRaw("urls", JsonStringArray(iocs.urls));
  obj.AddRaw("ips", JsonStringArray(iocs.ips));
  obj.AddRaw("domains", JsonStringArray(iocs.domains));
  obj.AddRaw("registryPaths", JsonStringArray(iocs.registryPaths));
  obj.AddRaw("filePaths", JsonStringArray(iocs.filePaths));
  obj.AddRaw("mutexHints", JsonStringArray(iocs.mutexHints));
  obj.AddRaw("base64Blobs", JsonStringArray(iocs.base64Blobs));
  obj.AddRaw("suspiciousApis", JsonStringArray(iocs.suspiciousApis));
  return obj.Finish();
}

static std::string TagsToJson(const std::vector<ScanTag> &tags) {
  std::ostringstream out;
  out << "[";
  for (size_t i = 0; i < tags.size(); ++i) {
    if (i) out << ",";
    JsonObjectBuilder obj;
    obj.AddString("tag", tags[i].tag);
    obj.AddString("category", tags[i].category);
    obj.AddNumber("confidence", tags[i].confidence);
    obj.AddRaw("reasons", JsonStringArray(tags[i].reasons));
    out << obj.Finish();
  }
  out << "]";
  return out.str();
}

static std::string YaraMatchesToJson(const std::vector<ScanYaraMatch> &m) {
  std::ostringstream out;
  out << "[";
  for (size_t i = 0; i < m.size(); ++i) {
    if (i) out << ",";
    JsonObjectBuilder obj;
    obj.AddString("ruleName", m[i].ruleName);
    obj.AddString("ruleNamespace", m[i].ruleNamespace);
    obj.AddRaw("tags", JsonStringArray(m[i].tags));
    obj.AddRaw("meta", JsonStringArray(m[i].meta));
    out << obj.Finish();
  }
  out << "]";
  return out.str();
}

static std::string CapaToJson(const std::vector<ScanCapaCapability> &c) {
  std::ostringstream out;
  out << "[";
  for (size_t i = 0; i < c.size(); ++i) {
    if (i) out << ",";
    JsonObjectBuilder obj;
    obj.AddString("name", c[i].name);
    obj.AddString("ruleNamespace", c[i].ruleNamespace);
    obj.AddRaw("mitreTechniques", JsonStringArray(c[i].mitreTechniques));
    obj.AddRaw("mbcBehaviors", JsonStringArray(c[i].mbcBehaviors));
    out << obj.Finish();
  }
  out << "]";
  return out.str();
}

static std::string DieToJson(const std::vector<ScanDieDetection> &d) {
  std::ostringstream out;
  out << "[";
  for (size_t i = 0; i < d.size(); ++i) {
    if (i) out << ",";
    JsonObjectBuilder obj;
    obj.AddString("type", d[i].type);
    obj.AddString("name", d[i].name);
    obj.AddString("version", d[i].version);
    obj.AddString("options", d[i].options);
    out << obj.Finish();
  }
  out << "]";
  return out.str();
}

static std::string IntelToJson(const std::vector<ScanIntelHit> &h) {
  std::ostringstream out;
  out << "[";
  for (size_t i = 0; i < h.size(); ++i) {
    if (i) out << ",";
    JsonObjectBuilder obj;
    obj.AddString("source", h[i].source);
    obj.AddBool("known", h[i].known);
    obj.AddString("family", h[i].family);
    obj.AddRaw("tags", JsonStringArray(h[i].tags));
    obj.AddNumber("detectionRatio", h[i].detectionRatio);
    obj.AddNumber("totalScanners", h[i].totalScanners);
    obj.AddString("firstSeen", h[i].firstSeen);
    obj.AddString("lastSeen", h[i].lastSeen);
    obj.AddString("permalink", h[i].permalink);
    obj.AddString("error", h[i].error);
    out << obj.Finish();
  }
  out << "]";
  return out.str();
}

std::string ToJson(const ScanResult &scan) {
  std::ostringstream findings;
  findings << "[";
  for (size_t i = 0; i < scan.findings.size(); ++i) {
    if (i) {
      findings << ",";
    }
    JsonObjectBuilder finding;
    finding.AddString("ruleId", scan.findings[i].ruleId);
    finding.AddString("message", scan.findings[i].message);
    finding.AddNumber("score", scan.findings[i].score);
    findings << finding.Finish();
  }
  findings << "]";

  JsonObjectBuilder obj;
  obj.AddString("path", PathToUtf8(scan.path));
  obj.AddString("sha256", scan.sha256);
  obj.AddString("md5", scan.md5);
  obj.AddString("imphash", scan.imphash);
  obj.AddDouble("entropy", scan.entropy);
  obj.AddBool("isPe", scan.isPe);
  obj.AddBool("authenticodeSigned", scan.authenticodeSigned);
  obj.AddRaw("imports", JsonStringArray(scan.imports));
  obj.AddRaw("findings", findings.str());
  obj.AddNumber("score", scan.score);
  obj.AddString("verdict", ToString(scan.verdict));
  obj.AddRaw("iocs", IocsToJson(scan.iocs));
  obj.AddRaw("tags", TagsToJson(scan.tags));
  obj.AddRaw("yaraMatches", YaraMatchesToJson(scan.yaraMatches));
  obj.AddRaw("capaCapabilities", CapaToJson(scan.capaCapabilities));
  obj.AddRaw("dieDetections", DieToJson(scan.dieDetections));
  obj.AddRaw("intelHits", IntelToJson(scan.intelHits));
  return obj.Finish();
}

static std::string EventToJson(const EventRecord &event) {
  std::ostringstream details;
  details << "{";
  size_t i = 0;
  for (const auto &[key, value] : event.details) {
    if (i++) {
      details << ",";
    }
    details << JsonQuote(key) << ":" << JsonQuote(value);
  }
  details << "}";

  JsonObjectBuilder obj;
  obj.AddString("timestampUtc", event.timestampUtc);
  obj.AddString("source", event.source);
  obj.AddString("category", event.category);
  obj.AddString("action", event.action);
  obj.AddNumber("processId", event.processId);
  obj.AddNumber("parentProcessId", event.parentProcessId);
  obj.AddString("imagePath", event.imagePath);
  obj.AddString("target", event.target);
  obj.AddRaw("details", details.str());
  obj.AddString("mitre", event.mitre);
  return obj.Finish();
}

static std::string BrowserRiskToJson(const BrowserRisk &risk) {
  JsonObjectBuilder obj;
  obj.AddString("site", risk.site);
  obj.AddString("domain", risk.domain);
  obj.AddBool("contactedBySample", risk.contactedBySample);
  obj.AddBool("savedCredentials", risk.savedCredentials);
  obj.AddBool("cookiesPresent", risk.cookiesPresent);
  obj.AddBool("decryptedEvidenceAvailable", risk.decryptedEvidenceAvailable);
  obj.AddString("lastVisited", risk.lastVisited);
  obj.AddString("recommendation", risk.recommendation);
  return obj.Finish();
}

std::string ToJson(const AnalysisReport &report) {
  std::ostringstream events;
  events << "[";
  for (size_t i = 0; i < report.events.size(); ++i) {
    if (i) {
      events << ",";
    }
    events << EventToJson(report.events[i]);
  }
  events << "]";

  std::ostringstream browser;
  browser << "[";
  for (size_t i = 0; i < report.browserImpact.size(); ++i) {
    if (i) {
      browser << ",";
    }
    browser << BrowserRiskToJson(report.browserImpact[i]);
  }
  browser << "]";

  JsonObjectBuilder obj;
  obj.AddNumber("schemaVersion", report.schemaVersion);
  obj.AddString("runId", report.runId);
  obj.AddString("samplePath", PathToUtf8(report.samplePath));
  obj.AddRaw("scannerVerdict", ToJson(report.scannerVerdict));
  obj.AddString("sandboxVerdict", ToString(report.sandboxVerdict));
  obj.AddRaw("dynamicSummary", ToJson(report.dynamicSummary));
  obj.AddRaw("events", events.str());
  obj.AddRaw("mitreTechniques", JsonStringArray(report.mitreTechniques));
  obj.AddRaw("artifacts", JsonPathArray(report.artifacts));
  obj.AddRaw("network", JsonStringArray(report.networkDomains));
  obj.AddRaw("browserImpact", browser.str());
  obj.AddRaw("errors", JsonStringArray(report.errors));
  return obj.Finish();
}

} // namespace antimal
