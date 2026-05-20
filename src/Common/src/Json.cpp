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
  obj.AddNumber("unhandledIo", summary.unhandledIo);
  obj.AddNumber("unhandledMmio", summary.unhandledMmio);
  obj.AddNumber("watchdogCancellations", summary.watchdogCancellations);
  obj.AddRaw("bootMilestones", JsonStringArray(summary.bootMilestones));
  obj.AddString("serialLogPath", PathToUtf8(summary.serialLogPath));
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
