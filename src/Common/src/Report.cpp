#include "antimal/Report.h"

#include "antimal/BootDiagnostics.h"
#include "antimal/CommandLineClassifier.h"
#include "antimal/CrashSummary.h"
#include "antimal/DetectionSummary.h"
#include "antimal/EventTime.h"
#include "antimal/UsabilityDiagnostics.h"
#include "antimal/FileUtil.h"
#include "antimal/Json.h"
#include "antimal/MitreCatalog.h"
#include "antimal/NetworkClassifier.h"
#include "antimal/PersistenceClassifier.h"
#include "antimal/ProcessChainClassifier.h"

#include <functional>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <cstdlib>

namespace antimal {
namespace {

// ----- Minimal JSON reader for AntiMal's own report schema --------------

struct JsonValue {
  enum class Type { Null, Bool, Number, String, Object, Array };
  Type type = Type::Null;
  bool boolean = false;
  double number = 0.0;
  std::string text;
  std::map<std::string, JsonValue> object;
  std::vector<JsonValue> array;
};

class JsonParser {
public:
  explicit JsonParser(const std::string &input) : input_(input) {}

  JsonValue Parse() {
    SkipWhitespace();
    return ParseValue();
  }

private:
  void SkipWhitespace() {
    while (pos_ < input_.size() &&
           std::isspace(static_cast<unsigned char>(input_[pos_]))) {
      ++pos_;
    }
  }

  bool Consume(char ch) {
    SkipWhitespace();
    if (pos_ < input_.size() && input_[pos_] == ch) {
      ++pos_;
      return true;
    }
    return false;
  }

  bool ConsumeLiteral(const char *literal) {
    SkipWhitespace();
    const size_t start = pos_;
    for (size_t i = 0; literal[i]; ++i) {
      if (pos_ + i >= input_.size() || input_[pos_ + i] != literal[i]) {
        pos_ = start;
        return false;
      }
    }
    pos_ += std::strlen(literal);
    return true;
  }

  JsonValue ParseValue() {
    SkipWhitespace();
    if (pos_ >= input_.size()) return {};
    if (input_[pos_] == '"') return ParseString();
    if (input_[pos_] == '{') return ParseObject();
    if (input_[pos_] == '[') return ParseArray();
    if (input_[pos_] == '-' || std::isdigit(static_cast<unsigned char>(input_[pos_]))) {
      return ParseNumber();
    }
    JsonValue value;
    if (ConsumeLiteral("true")) {
      value.type = JsonValue::Type::Bool;
      value.boolean = true;
    } else if (ConsumeLiteral("false")) {
      value.type = JsonValue::Type::Bool;
      value.boolean = false;
    } else {
      (void)ConsumeLiteral("null");
    }
    return value;
  }

  JsonValue ParseString() {
    JsonValue value;
    value.type = JsonValue::Type::String;
    if (!Consume('"')) return value;
    while (pos_ < input_.size()) {
      const char ch = input_[pos_++];
      if (ch == '"') break;
      if (ch != '\\' || pos_ >= input_.size()) {
        value.text.push_back(ch);
        continue;
      }
      const char esc = input_[pos_++];
      switch (esc) {
      case '"': value.text.push_back('"'); break;
      case '\\': value.text.push_back('\\'); break;
      case '/': value.text.push_back('/'); break;
      case 'b': value.text.push_back('\b'); break;
      case 'f': value.text.push_back('\f'); break;
      case 'n': value.text.push_back('\n'); break;
      case 'r': value.text.push_back('\r'); break;
      case 't': value.text.push_back('\t'); break;
      case 'u':
        // AntiMal emits UTF-8 strings and only escapes control chars, so
        // report fields should not need full Unicode escape decoding.
        if (pos_ + 4 <= input_.size()) pos_ += 4;
        value.text.push_back('?');
        break;
      default:
        value.text.push_back(esc);
        break;
      }
    }
    return value;
  }

  JsonValue ParseNumber() {
    JsonValue value;
    value.type = JsonValue::Type::Number;
    const size_t start = pos_;
    if (input_[pos_] == '-') ++pos_;
    while (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_]))) ++pos_;
    if (pos_ < input_.size() && input_[pos_] == '.') {
      ++pos_;
      while (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_]))) ++pos_;
    }
    if (pos_ < input_.size() && (input_[pos_] == 'e' || input_[pos_] == 'E')) {
      ++pos_;
      if (pos_ < input_.size() && (input_[pos_] == '+' || input_[pos_] == '-')) ++pos_;
      while (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_]))) ++pos_;
    }
    value.number = std::strtod(input_.c_str() + start, nullptr);
    return value;
  }

  JsonValue ParseObject() {
    JsonValue value;
    value.type = JsonValue::Type::Object;
    if (!Consume('{')) return value;
    if (Consume('}')) return value;
    while (pos_ < input_.size()) {
      JsonValue key = ParseString();
      if (!Consume(':')) break;
      value.object[key.text] = ParseValue();
      if (Consume('}')) break;
      if (!Consume(',')) break;
    }
    return value;
  }

  JsonValue ParseArray() {
    JsonValue value;
    value.type = JsonValue::Type::Array;
    if (!Consume('[')) return value;
    if (Consume(']')) return value;
    while (pos_ < input_.size()) {
      value.array.push_back(ParseValue());
      if (Consume(']')) break;
      if (!Consume(',')) break;
    }
    return value;
  }

  const std::string &input_;
  size_t pos_ = 0;
};

const JsonValue *Member(const JsonValue &object, const std::string &key) {
  if (object.type != JsonValue::Type::Object) return nullptr;
  const auto it = object.object.find(key);
  return it == object.object.end() ? nullptr : &it->second;
}

std::string StringValue(const JsonValue *value, std::string fallback = {}) {
  return value && value->type == JsonValue::Type::String ? value->text : fallback;
}

int IntValue(const JsonValue *value, int fallback = 0) {
  return value && value->type == JsonValue::Type::Number
             ? static_cast<int>(value->number)
             : fallback;
}

double DoubleValue(const JsonValue *value, double fallback = 0.0) {
  return value && value->type == JsonValue::Type::Number ? value->number : fallback;
}

bool BoolValue(const JsonValue *value, bool fallback = false) {
  return value && value->type == JsonValue::Type::Bool ? value->boolean : fallback;
}

std::vector<std::string> StringArrayValue(const JsonValue *value) {
  std::vector<std::string> out;
  if (!value || value->type != JsonValue::Type::Array) return out;
  for (const auto &item : value->array) {
    if (item.type == JsonValue::Type::String) out.push_back(item.text);
  }
  return out;
}

std::vector<std::filesystem::path> PathArrayValue(const JsonValue *value) {
  std::vector<std::filesystem::path> out;
  for (const auto &item : StringArrayValue(value)) {
    out.push_back(Utf8ToWide(item));
  }
  return out;
}

Verdict ParseVerdictValue(const JsonValue *value) {
  const auto text = StringValue(value);
  if (text == "malicious") return Verdict::Malicious;
  if (text == "suspicious") return Verdict::Suspicious;
  if (text == "clean") return Verdict::Clean;
  if (text == "unknown") return Verdict::Unknown;
  return Verdict::Error;
}

ScanIocSet ParseIocs(const JsonValue *value) {
  ScanIocSet iocs;
  if (!value) return iocs;
  iocs.urls = StringArrayValue(Member(*value, "urls"));
  iocs.ips = StringArrayValue(Member(*value, "ips"));
  iocs.domains = StringArrayValue(Member(*value, "domains"));
  iocs.registryPaths = StringArrayValue(Member(*value, "registryPaths"));
  iocs.filePaths = StringArrayValue(Member(*value, "filePaths"));
  iocs.mutexHints = StringArrayValue(Member(*value, "mutexHints"));
  iocs.base64Blobs = StringArrayValue(Member(*value, "base64Blobs"));
  iocs.suspiciousApis = StringArrayValue(Member(*value, "suspiciousApis"));
  return iocs;
}

std::vector<ScanFinding> ParseFindings(const JsonValue *value) {
  std::vector<ScanFinding> findings;
  if (!value || value->type != JsonValue::Type::Array) return findings;
  for (const auto &item : value->array) {
    ScanFinding finding;
    finding.ruleId = StringValue(Member(item, "ruleId"));
    finding.message = StringValue(Member(item, "message"));
    finding.score = IntValue(Member(item, "score"));
    findings.push_back(std::move(finding));
  }
  return findings;
}

std::vector<PeSection> ParseSections(const JsonValue *value) {
  std::vector<PeSection> sections;
  if (!value || value->type != JsonValue::Type::Array) return sections;
  for (const auto &item : value->array) {
    PeSection sec;
    sec.name = StringValue(Member(item, "name"));
    // DoubleValue (not IntValue): section characteristics flags exceed INT_MAX.
    sec.virtualSize = static_cast<uint32_t>(DoubleValue(Member(item, "virtualSize")));
    sec.rawSize = static_cast<uint32_t>(DoubleValue(Member(item, "rawSize")));
    sec.characteristics =
        static_cast<uint32_t>(DoubleValue(Member(item, "characteristics")));
    sec.entropy = DoubleValue(Member(item, "entropy"));
    sec.executable = BoolValue(Member(item, "executable"));
    sec.writable = BoolValue(Member(item, "writable"));
    sections.push_back(std::move(sec));
  }
  return sections;
}

std::vector<ScanTag> ParseTags(const JsonValue *value) {
  std::vector<ScanTag> tags;
  if (!value || value->type != JsonValue::Type::Array) return tags;
  for (const auto &item : value->array) {
    ScanTag tag;
    tag.tag = StringValue(Member(item, "tag"));
    tag.category = StringValue(Member(item, "category"));
    tag.confidence = IntValue(Member(item, "confidence"));
    tag.reasons = StringArrayValue(Member(item, "reasons"));
    tags.push_back(std::move(tag));
  }
  return tags;
}

std::vector<ScanYaraMatch> ParseYara(const JsonValue *value) {
  std::vector<ScanYaraMatch> matches;
  if (!value || value->type != JsonValue::Type::Array) return matches;
  for (const auto &item : value->array) {
    ScanYaraMatch match;
    match.ruleName = StringValue(Member(item, "ruleName"));
    match.ruleNamespace = StringValue(Member(item, "ruleNamespace"));
    match.tags = StringArrayValue(Member(item, "tags"));
    match.meta = StringArrayValue(Member(item, "meta"));
    matches.push_back(std::move(match));
  }
  return matches;
}

std::vector<ScanCapaCapability> ParseCapa(const JsonValue *value) {
  std::vector<ScanCapaCapability> caps;
  if (!value || value->type != JsonValue::Type::Array) return caps;
  for (const auto &item : value->array) {
    ScanCapaCapability cap;
    cap.name = StringValue(Member(item, "name"));
    cap.ruleNamespace = StringValue(Member(item, "ruleNamespace"));
    cap.mitreTechniques = StringArrayValue(Member(item, "mitreTechniques"));
    cap.mbcBehaviors = StringArrayValue(Member(item, "mbcBehaviors"));
    caps.push_back(std::move(cap));
  }
  return caps;
}

std::vector<ScanDieDetection> ParseDie(const JsonValue *value) {
  std::vector<ScanDieDetection> detections;
  if (!value || value->type != JsonValue::Type::Array) return detections;
  for (const auto &item : value->array) {
    ScanDieDetection die;
    die.type = StringValue(Member(item, "type"));
    die.name = StringValue(Member(item, "name"));
    die.version = StringValue(Member(item, "version"));
    die.options = StringValue(Member(item, "options"));
    detections.push_back(std::move(die));
  }
  return detections;
}

std::vector<ScanIntelHit> ParseIntel(const JsonValue *value) {
  std::vector<ScanIntelHit> hits;
  if (!value || value->type != JsonValue::Type::Array) return hits;
  for (const auto &item : value->array) {
    ScanIntelHit hit;
    hit.source = StringValue(Member(item, "source"));
    hit.known = BoolValue(Member(item, "known"));
    hit.family = StringValue(Member(item, "family"));
    hit.tags = StringArrayValue(Member(item, "tags"));
    hit.detectionRatio = IntValue(Member(item, "detectionRatio"));
    hit.totalScanners = IntValue(Member(item, "totalScanners"));
    hit.firstSeen = StringValue(Member(item, "firstSeen"));
    hit.lastSeen = StringValue(Member(item, "lastSeen"));
    hit.permalink = StringValue(Member(item, "permalink"));
    hit.error = StringValue(Member(item, "error"));
    hits.push_back(std::move(hit));
  }
  return hits;
}

ScanResult ParseScan(const JsonValue *value) {
  ScanResult scan;
  if (!value) return scan;
  scan.path = Utf8ToWide(StringValue(Member(*value, "path")));
  scan.sha256 = StringValue(Member(*value, "sha256"));
  scan.sha1 = StringValue(Member(*value, "sha1"));
  scan.md5 = StringValue(Member(*value, "md5"));
  scan.imphash = StringValue(Member(*value, "imphash"));
  scan.ctph = StringValue(Member(*value, "ctph"));
  scan.detectedType = StringValue(Member(*value, "detectedType"));
  scan.entropy = DoubleValue(Member(*value, "entropy"));
  scan.isPe = BoolValue(Member(*value, "isPe"));
  scan.authenticodeSigned = BoolValue(Member(*value, "authenticodeSigned"));
  scan.signerName = StringValue(Member(*value, "signerName"));
  scan.imports = StringArrayValue(Member(*value, "imports"));
  scan.peTimestamp = static_cast<uint32_t>(DoubleValue(Member(*value, "peTimestamp")));
  scan.peOverlaySize =
      static_cast<uint64_t>(DoubleValue(Member(*value, "peOverlaySize")));
  scan.peOverlayEntropy = DoubleValue(Member(*value, "peOverlayEntropy"));
  scan.embeddedExecutables = IntValue(Member(*value, "embeddedExecutables"));
  scan.isDll = BoolValue(Member(*value, "isDll"));
  scan.isDotNet = BoolValue(Member(*value, "isDotNet"));
  scan.dotNetRuntimeVersion = StringValue(Member(*value, "dotNetRuntimeVersion"));
  scan.exportName = StringValue(Member(*value, "exportName"));
  scan.peExports = StringArrayValue(Member(*value, "exports"));
  scan.tlsCallbackCount =
      static_cast<uint32_t>(IntValue(Member(*value, "tlsCallbackCount")));
  scan.pdbPath = StringValue(Member(*value, "pdbPath"));
  scan.richHash = StringValue(Member(*value, "richHash"));
  if (const JsonValue *vi = Member(*value, "versionInfo")) {
    scan.peVersionInfo.present = BoolValue(Member(*vi, "present"));
    scan.peVersionInfo.companyName = StringValue(Member(*vi, "companyName"));
    scan.peVersionInfo.productName = StringValue(Member(*vi, "productName"));
    scan.peVersionInfo.fileDescription = StringValue(Member(*vi, "fileDescription"));
    scan.peVersionInfo.originalFilename = StringValue(Member(*vi, "originalFilename"));
    scan.peVersionInfo.internalName = StringValue(Member(*vi, "internalName"));
    scan.peVersionInfo.fileVersion = StringValue(Member(*vi, "fileVersion"));
    scan.peVersionInfo.productVersion = StringValue(Member(*vi, "productVersion"));
    scan.peVersionInfo.legalCopyright = StringValue(Member(*vi, "legalCopyright"));
  }
  scan.peSections = ParseSections(Member(*value, "peSections"));
  scan.findings = ParseFindings(Member(*value, "findings"));
  scan.score = IntValue(Member(*value, "score"));
  scan.verdict = ParseVerdictValue(Member(*value, "verdict"));
  scan.iocs = ParseIocs(Member(*value, "iocs"));
  scan.tags = ParseTags(Member(*value, "tags"));
  scan.yaraMatches = ParseYara(Member(*value, "yaraMatches"));
  scan.capaCapabilities = ParseCapa(Member(*value, "capaCapabilities"));
  scan.dieDetections = ParseDie(Member(*value, "dieDetections"));
  scan.intelHits = ParseIntel(Member(*value, "intelHits"));
  return scan;
}

std::vector<EventRecord> ParseEvents(const JsonValue *value) {
  std::vector<EventRecord> events;
  if (!value || value->type != JsonValue::Type::Array) return events;
  for (const auto &item : value->array) {
    EventRecord event;
    event.timestampUtc = StringValue(Member(item, "timestampUtc"));
    event.source = StringValue(Member(item, "source"));
    event.category = StringValue(Member(item, "category"));
    event.action = StringValue(Member(item, "action"));
    event.processId = static_cast<uint32_t>(IntValue(Member(item, "processId")));
    event.parentProcessId =
        static_cast<uint32_t>(IntValue(Member(item, "parentProcessId")));
    event.imagePath = StringValue(Member(item, "imagePath"));
    event.fullImagePath = StringValue(Member(item, "fullImagePath"));
    event.commandLine = StringValue(Member(item, "commandLine"));
    event.integrityLevel = StringValue(Member(item, "integrityLevel"));
    event.userName = StringValue(Member(item, "userName"));
    event.target = StringValue(Member(item, "target"));
    event.mitre = StringValue(Member(item, "mitre"));
    if (const auto *details = Member(item, "details");
        details && details->type == JsonValue::Type::Object) {
      for (const auto &[key, detail] : details->object) {
        event.details[key] = StringValue(&detail);
      }
    }
    events.push_back(std::move(event));
  }
  return events;
}

std::vector<BrowserRisk> ParseBrowserRisk(const JsonValue *value) {
  std::vector<BrowserRisk> risks;
  if (!value || value->type != JsonValue::Type::Array) return risks;
  for (const auto &item : value->array) {
    BrowserRisk risk;
    risk.site = StringValue(Member(item, "site"));
    risk.domain = StringValue(Member(item, "domain"));
    risk.contactedBySample = BoolValue(Member(item, "contactedBySample"));
    risk.savedCredentials = BoolValue(Member(item, "savedCredentials"));
    risk.cookiesPresent = BoolValue(Member(item, "cookiesPresent"));
    risk.decryptedEvidenceAvailable =
        BoolValue(Member(item, "decryptedEvidenceAvailable"));
    risk.lastVisited = StringValue(Member(item, "lastVisited"));
    risk.recommendation = StringValue(Member(item, "recommendation"));
    risks.push_back(std::move(risk));
  }
  return risks;
}

DynamicRunSummary ParseDynamicSummary(const JsonValue *value) {
  DynamicRunSummary summary;
  if (!value || value->type != JsonValue::Type::Object) return summary;
  summary.started = BoolValue(Member(*value, "started"));
  summary.completed = BoolValue(Member(*value, "completed"));
  summary.timedOut = BoolValue(Member(*value, "timedOut"));
  summary.crashed = BoolValue(Member(*value, "crashed"));
  summary.sampleExecuted = BoolValue(Member(*value, "sampleExecuted"));
  summary.firmwareIdle = BoolValue(Member(*value, "firmwareIdle"));
  summary.guestAgentConnected =
      BoolValue(Member(*value, "guestAgentConnected"));
  summary.status = StringValue(Member(*value, "status"));
  if (const auto network =
          ParseNetworkMode(StringValue(Member(*value, "networkMode")))) {
    summary.networkMode = *network;
  }
  summary.framesCaptured =
      static_cast<uint32_t>(IntValue(Member(*value, "framesCaptured")));
  summary.eventsCaptured =
      static_cast<uint32_t>(IntValue(Member(*value, "eventsCaptured")));
  summary.artifactsCaptured =
      static_cast<uint32_t>(IntValue(Member(*value, "artifactsCaptured")));
  summary.vcpuExits =
      static_cast<uint32_t>(IntValue(Member(*value, "vcpuExits")));
  summary.hltCount =
      static_cast<uint32_t>(IntValue(Member(*value, "hltCount")));
  summary.ideCommandsIssued =
      static_cast<uint32_t>(IntValue(Member(*value, "ideCommandsIssued")));
  summary.ideIdentifyCommands =
      static_cast<uint32_t>(IntValue(Member(*value, "ideIdentifyCommands")));
  summary.ideReadCommands =
      static_cast<uint32_t>(IntValue(Member(*value, "ideReadCommands")));
  summary.ideWriteCommands =
      static_cast<uint32_t>(IntValue(Member(*value, "ideWriteCommands")));
  summary.ideAbortedCommands =
      static_cast<uint32_t>(IntValue(Member(*value, "ideAbortedCommands")));
  summary.ideSectorsRead =
      static_cast<uint64_t>(IntValue(Member(*value, "ideSectorsRead")));
  summary.ideSectorsWritten =
      static_cast<uint64_t>(IntValue(Member(*value, "ideSectorsWritten")));
  summary.ideSawRead = BoolValue(Member(*value, "ideSawRead"));
  summary.ideSawWrite = BoolValue(Member(*value, "ideSawWrite"));
  summary.ideMinReadLba =
      static_cast<uint64_t>(IntValue(Member(*value, "ideMinReadLba")));
  summary.ideMaxReadEndLba =
      static_cast<uint64_t>(IntValue(Member(*value, "ideMaxReadEndLba")));
  summary.ideMinWriteLba =
      static_cast<uint64_t>(IntValue(Member(*value, "ideMinWriteLba")));
  summary.ideMaxWriteEndLba =
      static_cast<uint64_t>(IntValue(Member(*value, "ideMaxWriteEndLba")));
  summary.unhandledIo =
      static_cast<uint32_t>(IntValue(Member(*value, "unhandledIo")));
  summary.unhandledMmio =
      static_cast<uint32_t>(IntValue(Member(*value, "unhandledMmio")));
  summary.watchdogCancellations =
      static_cast<uint32_t>(IntValue(Member(*value, "watchdogCancellations")));
  summary.ideInterruptsRequested =
      static_cast<uint32_t>(IntValue(Member(*value, "ideInterruptsRequested")));
  summary.ideInterruptsInjected =
      static_cast<uint32_t>(IntValue(Member(*value, "ideInterruptsInjected")));
  summary.ideInterruptsFailed =
      static_cast<uint32_t>(IntValue(Member(*value, "ideInterruptsFailed")));
  summary.ideInterruptsPending =
      static_cast<uint32_t>(IntValue(Member(*value, "ideInterruptsPending")));
  summary.ideInterruptsIoApic =
      static_cast<uint32_t>(IntValue(Member(*value, "ideInterruptsIoApic")));
  summary.ideInterruptsPicFallback = static_cast<uint32_t>(
      IntValue(Member(*value, "ideInterruptsPicFallback")));
  summary.pitInterruptsPending =
      static_cast<uint32_t>(IntValue(Member(*value, "pitInterruptsPending")));
  summary.rtcInterruptsPending =
      static_cast<uint32_t>(IntValue(Member(*value, "rtcInterruptsPending")));
  summary.irqIoApicDeliveries =
      static_cast<uint32_t>(IntValue(Member(*value, "irqIoApicDeliveries")));
  summary.irqPicFallbackDeliveries = static_cast<uint32_t>(
      IntValue(Member(*value, "irqPicFallbackDeliveries")));
  summary.irqDeliveryFailures =
      static_cast<uint32_t>(IntValue(Member(*value, "irqDeliveryFailures")));
  summary.masterPicVectorBase =
      static_cast<uint32_t>(IntValue(Member(*value, "masterPicVectorBase")));
  summary.slavePicVectorBase =
      static_cast<uint32_t>(IntValue(Member(*value, "slavePicVectorBase")));
  summary.masterPicMask =
      static_cast<uint32_t>(IntValue(Member(*value, "masterPicMask")));
  summary.slavePicMask =
      static_cast<uint32_t>(IntValue(Member(*value, "slavePicMask")));
  summary.pm1SleepEnable = BoolValue(Member(*value, "pm1SleepEnable"));
  summary.pm1HostStopRequested =
      BoolValue(Member(*value, "pm1HostStopRequested"));
  summary.pm1SleepType =
      static_cast<uint32_t>(IntValue(Member(*value, "pm1SleepType")));
  summary.pm1ControlValue =
      static_cast<uint32_t>(IntValue(Member(*value, "pm1ControlValue")));
  summary.pm1EnableValue =
      static_cast<uint32_t>(IntValue(Member(*value, "pm1EnableValue")));
  summary.pm1aStatusReads =
      static_cast<uint64_t>(IntValue(Member(*value, "pm1aStatusReads")));
  summary.screenStateReached =
      static_cast<uint32_t>(IntValue(Member(*value, "screenStateReached")));
  summary.liveFramePacingSummary =
      StringValue(Member(*value, "liveFramePacingSummary"));
  summary.pm1SleepRequests =
      static_cast<uint64_t>(IntValue(Member(*value, "pm1SleepRequests")));
  summary.kdPacketsReceived =
      static_cast<uint64_t>(IntValue(Member(*value, "kdPacketsReceived")));
  summary.kdControlPacketsReceived = static_cast<uint64_t>(
      IntValue(Member(*value, "kdControlPacketsReceived")));
  summary.kdDataPacketsReceived =
      static_cast<uint64_t>(IntValue(Member(*value, "kdDataPacketsReceived")));
  summary.kdAckPacketsSent =
      static_cast<uint64_t>(IntValue(Member(*value, "kdAckPacketsSent")));
  summary.kdResendPacketsSent =
      static_cast<uint64_t>(IntValue(Member(*value, "kdResendPacketsSent")));
  summary.kdResetPacketsReceived =
      static_cast<uint64_t>(IntValue(Member(*value, "kdResetPacketsReceived")));
  summary.kdResetPacketsSent =
      static_cast<uint64_t>(IntValue(Member(*value, "kdResetPacketsSent")));
  summary.kdCom1RxQueuedBytes =
      static_cast<uint64_t>(IntValue(Member(*value, "kdCom1RxQueuedBytes")));
  summary.kdTargetAcksReceived =
      static_cast<uint64_t>(IntValue(Member(*value, "kdTargetAcksReceived")));
  summary.kdDebugPrintBytes =
      static_cast<uint64_t>(IntValue(Member(*value, "kdDebugPrintBytes")));
  summary.kdDebugPrintPackets =
      static_cast<uint64_t>(IntValue(Member(*value, "kdDebugPrintPackets")));
  summary.kdStateChangePackets =
      static_cast<uint64_t>(IntValue(Member(*value, "kdStateChangePackets")));
  summary.kdLoadSymbolPackets =
      static_cast<uint64_t>(IntValue(Member(*value, "kdLoadSymbolPackets")));
  summary.kdStatusPackets =
      static_cast<uint64_t>(IntValue(Member(*value, "kdStatusPackets")));
  summary.kdAutoContinuesSent =
      static_cast<uint64_t>(IntValue(Member(*value, "kdAutoContinuesSent")));
  summary.kdChecksumFailures =
      static_cast<uint64_t>(IntValue(Member(*value, "kdChecksumFailures")));
  summary.kdTrailingByteFailures =
      static_cast<uint64_t>(IntValue(Member(*value, "kdTrailingByteFailures")));
  summary.kdLastPacketType =
      static_cast<uint32_t>(IntValue(Member(*value, "kdLastPacketType")));
  summary.kdLastApiNumber =
      static_cast<uint32_t>(IntValue(Member(*value, "kdLastApiNumber")));
  summary.kdLastStatus =
      static_cast<uint32_t>(IntValue(Member(*value, "kdLastStatus")));
  summary.kdLastStatusText = StringValue(Member(*value, "kdLastStatusText"));
  summary.kdCom1Status = StringValue(Member(*value, "kdCom1Status"));
  summary.com1RegisterReads =
      static_cast<uint64_t>(IntValue(Member(*value, "com1RegisterReads")));
  summary.com1RegisterWrites =
      static_cast<uint64_t>(IntValue(Member(*value, "com1RegisterWrites")));
  summary.com1DataReads =
      static_cast<uint64_t>(IntValue(Member(*value, "com1DataReads")));
  summary.com1DataWrites =
      static_cast<uint64_t>(IntValue(Member(*value, "com1DataWrites")));
  summary.com1RxBytesQueued =
      static_cast<uint64_t>(IntValue(Member(*value, "com1RxBytesQueued")));
  summary.com1RxBytesRead =
      static_cast<uint64_t>(IntValue(Member(*value, "com1RxBytesRead")));
  summary.com1RxBytesCleared =
      static_cast<uint64_t>(IntValue(Member(*value, "com1RxBytesCleared")));
  summary.com1IerWrites =
      static_cast<uint64_t>(IntValue(Member(*value, "com1IerWrites")));
  summary.com1FcrWrites =
      static_cast<uint64_t>(IntValue(Member(*value, "com1FcrWrites")));
  summary.com1LcrWrites =
      static_cast<uint64_t>(IntValue(Member(*value, "com1LcrWrites")));
  summary.com1McrWrites =
      static_cast<uint64_t>(IntValue(Member(*value, "com1McrWrites")));
  summary.com1DllWrites =
      static_cast<uint64_t>(IntValue(Member(*value, "com1DllWrites")));
  summary.com1DlmWrites =
      static_cast<uint64_t>(IntValue(Member(*value, "com1DlmWrites")));
  summary.com1IirReads =
      static_cast<uint64_t>(IntValue(Member(*value, "com1IirReads")));
  summary.com1LsrReads =
      static_cast<uint64_t>(IntValue(Member(*value, "com1LsrReads")));
  summary.com1Ier = static_cast<uint32_t>(IntValue(Member(*value, "com1Ier")));
  summary.com1Fcr = static_cast<uint32_t>(IntValue(Member(*value, "com1Fcr")));
  summary.com1Lcr = static_cast<uint32_t>(IntValue(Member(*value, "com1Lcr")));
  summary.com1Mcr = static_cast<uint32_t>(IntValue(Member(*value, "com1Mcr")));
  summary.com1Dll = static_cast<uint32_t>(IntValue(Member(*value, "com1Dll")));
  summary.com1Dlm = static_cast<uint32_t>(IntValue(Member(*value, "com1Dlm")));
  summary.com1Dlab = BoolValue(Member(*value, "com1Dlab"));
  summary.com1RxInterruptEnabled =
      BoolValue(Member(*value, "com1RxInterruptEnabled"));
  summary.com1RxDataReady = BoolValue(Member(*value, "com1RxDataReady"));
  summary.com1TouchStatus = StringValue(Member(*value, "com1TouchStatus"));
  summary.tpmCrbReads =
      static_cast<uint64_t>(IntValue(Member(*value, "tpmCrbReads")));
  summary.tpmCrbWrites =
      static_cast<uint64_t>(IntValue(Member(*value, "tpmCrbWrites")));
  summary.tpmCrbCommands =
      static_cast<uint64_t>(IntValue(Member(*value, "tpmCrbCommands")));
  summary.tpmCrbLastCommand =
      static_cast<uint32_t>(IntValue(Member(*value, "tpmCrbLastCommand")));
  summary.tpmCrbLastResponse =
      static_cast<uint32_t>(IntValue(Member(*value, "tpmCrbLastResponse")));
  summary.tpmCrbLastReadOffset =
      static_cast<uint64_t>(IntValue(Member(*value, "tpmCrbLastReadOffset")));
  summary.tpmCrbLastWriteOffset =
      static_cast<uint64_t>(IntValue(Member(*value, "tpmCrbLastWriteOffset")));
  summary.tpmCrbCommandSummary =
      StringValue(Member(*value, "tpmCrbCommandSummary"));
  summary.tpmPcrExtendTraceSummary =
      StringValue(Member(*value, "tpmPcrExtendTraceSummary"));
  summary.tpmPcrFinalBanksSummary =
      StringValue(Member(*value, "tpmPcrFinalBanksSummary"));
  summary.acpiTpm2EventLogSummary =
      StringValue(Member(*value, "acpiTpm2EventLogSummary"));
  summary.fwCfgSmbiosTableBytesRead = static_cast<uint64_t>(
      IntValue(Member(*value, "fwCfgSmbiosTableBytesRead")));
  summary.fwCfgSmbiosAnchorBytesRead = static_cast<uint64_t>(
      IntValue(Member(*value, "fwCfgSmbiosAnchorBytesRead")));
  summary.keyboardScancodesInjected = static_cast<uint32_t>(
      IntValue(Member(*value, "keyboardScancodesInjected")));
  summary.ps2StatusReads =
      static_cast<uint64_t>(IntValue(Member(*value, "ps2StatusReads")));
  summary.ps2DataReads =
      static_cast<uint64_t>(IntValue(Member(*value, "ps2DataReads")));
  summary.ps2CommandWrites =
      static_cast<uint64_t>(IntValue(Member(*value, "ps2CommandWrites")));
  summary.ps2DataWrites =
      static_cast<uint64_t>(IntValue(Member(*value, "ps2DataWrites")));
  summary.ps2KeyboardBytesQueued = static_cast<uint64_t>(
      IntValue(Member(*value, "ps2KeyboardBytesQueued")));
  summary.ps2KeyboardBytesRead = static_cast<uint64_t>(
      IntValue(Member(*value, "ps2KeyboardBytesRead")));
  summary.ps2MouseBytesQueued = static_cast<uint64_t>(
      IntValue(Member(*value, "ps2MouseBytesQueued")));
  summary.ps2MouseBytesRead = static_cast<uint64_t>(
      IntValue(Member(*value, "ps2MouseBytesRead")));
  summary.ps2KeyboardPortEnabled =
      BoolValue(Member(*value, "ps2KeyboardPortEnabled"));
  summary.ps2MousePortEnabled =
      BoolValue(Member(*value, "ps2MousePortEnabled"));
  summary.ps2KeyboardScanningEnabled =
      BoolValue(Member(*value, "ps2KeyboardScanningEnabled"));
  summary.ps2InputStatus = StringValue(Member(*value, "ps2InputStatus"));
  summary.windowsKernelReadGateReached =
      BoolValue(Member(*value, "windowsKernelReadGateReached"));
  summary.windowsKernelReadGateStatus =
      StringValue(Member(*value, "windowsKernelReadGateStatus"));
  summary.windowsKernelReadGateEvidence =
      StringValue(Member(*value, "windowsKernelReadGateEvidence"));
  summary.windowsKernelReadGateFirstTarget =
      StringValue(Member(*value, "windowsKernelReadGateFirstTarget"));
  summary.windowsUserModeGateReached =
      BoolValue(Member(*value, "windowsUserModeGateReached"));
  summary.windowsUserModeGateStatus =
      StringValue(Member(*value, "windowsUserModeGateStatus"),
                  StringValue(Member(*value, "userModeGate")));
  summary.windowsUserModeGateEvidence =
      StringValue(Member(*value, "windowsUserModeGateEvidence"));
  summary.windowsUserModeGateFirstTarget =
      StringValue(Member(*value, "windowsUserModeGateFirstTarget"),
                  StringValue(Member(*value, "firstUserModeTarget")));
  summary.bootFailureStatus =
      StringValue(Member(*value, "bootFailureStatus"));
  summary.bootFailureStatusName =
      StringValue(Member(*value, "bootFailureStatusName"));
  summary.bootFailureStatusSource =
      StringValue(Member(*value, "bootFailureStatusSource"));
  summary.bootBlocker = StringValue(Member(*value, "bootBlocker"));
  summary.bootContractSuspect =
      StringValue(Member(*value, "bootContractSuspect"));
  summary.bootContractSuspectDetails =
      StringValue(Member(*value, "bootContractSuspectDetails"));
  summary.ciPolicyInventory = StringValue(Member(*value, "ciPolicyInventory"));
  summary.bootstatScalarSummary =
      StringValue(Member(*value, "bootstatScalarSummary"));
  summary.cpuidDiagnostics = StringArrayValue(Member(*value, "cpuidDiagnostics"));
  summary.bootStage = StringValue(Member(*value, "bootStage"));
  summary.bootMilestones = StringArrayValue(Member(*value, "bootMilestones"));
  summary.interruptDiagnostics =
      StringArrayValue(Member(*value, "interruptDiagnostics"));
  summary.serialLogPath =
      Utf8ToWide(StringValue(Member(*value, "serialLogPath")));
  summary.kdLogPath = Utf8ToWide(StringValue(Member(*value, "kdLogPath")));
  summary.kdPacketsPath =
      Utf8ToWide(StringValue(Member(*value, "kdPacketsPath")));
  summary.vmSummaryPath =
      Utf8ToWide(StringValue(Member(*value, "vmSummaryPath")));
  return summary;
}

AnalysisReport ParseReportJson(const std::string &text,
                               const std::filesystem::path &path) {
  JsonParser parser(text);
  const auto root = parser.Parse();
  AnalysisReport report;
  report.runId = StringValue(Member(root, "runId"), path.stem().string());
  report.schemaVersion = IntValue(Member(root, "schemaVersion"), 1);
  report.samplePath = Utf8ToWide(StringValue(Member(root, "samplePath")));
  report.scannerVerdict = ParseScan(Member(root, "scannerVerdict"));
  report.sandboxVerdict = ParseVerdictValue(Member(root, "sandboxVerdict"));
  report.verdictScore = IntValue(Member(root, "verdictScore"), 0);
  report.verdictRationale = StringArrayValue(Member(root, "verdictRationale"));
  report.dynamicSummary = ParseDynamicSummary(Member(root, "dynamicSummary"));
  report.events = ParseEvents(Member(root, "events"));
  report.mitreTechniques = StringArrayValue(Member(root, "mitreTechniques"));
  report.artifacts = PathArrayValue(Member(root, "artifacts"));
  report.networkDomains = StringArrayValue(Member(root, "network"));
  if (report.networkDomains.empty()) {
    report.networkDomains = StringArrayValue(Member(root, "networkDomains"));
  }
  report.browserImpact = ParseBrowserRisk(Member(root, "browserImpact"));
  report.errors = StringArrayValue(Member(root, "errors"));
  return report;
}

std::string HtmlPath(std::filesystem::path path) {
  std::string text = PathToUtf8(path);
  std::replace(text.begin(), text.end(), '\\', '/');
  return text;
}

// ----- HTML building blocks --------------------------------------------

struct ProcNode {
  uint32_t pid = 0;
  uint32_t parentPid = 0;
  std::string imagePath;
  std::set<std::string> categories;  // for chip badges (file, registry, network, ...)
  int eventCount = 0;
  std::vector<ProcNode *> children;
};

struct ProcessForest {
  std::map<uint32_t, ProcNode> nodes;
  std::vector<ProcNode *> roots;
};

ProcessForest BuildProcessForest(const std::vector<EventRecord> &events) {
  ProcessForest forest;
  for (const auto &e : events) {
    auto &node = forest.nodes[e.processId];
    node.pid = e.processId;
    if (node.parentPid == 0 && e.parentProcessId != 0) {
      node.parentPid = e.parentProcessId;
    }
    if (node.imagePath.empty() && !e.imagePath.empty()) {
      node.imagePath = e.imagePath;
    }
    if (!e.category.empty()) node.categories.insert(e.category);
    ++node.eventCount;
  }
  for (auto &[pid, node] : forest.nodes) {
    if (node.parentPid == 0 || forest.nodes.count(node.parentPid) == 0) {
      forest.roots.push_back(&node);
    } else {
      forest.nodes[node.parentPid].children.push_back(&node);
    }
  }
  return forest;
}

std::string EmitProcessTreeHtml(const ProcessForest &forest);

void EmitProcessNode(std::ostringstream &out, const ProcNode *node) {
  out << "<li class=\"proc\" data-pid=\"" << node->pid << "\">";
  out << "<div class=\"proc-row\" onclick=\"AntiMal.filterByPid(" << node->pid << ")\">";
  out << "<span class=\"pid\">" << node->pid << "</span>";
  out << "<span class=\"name\">" << HtmlEscape(
      node->imagePath.empty() ? ("pid " + std::to_string(node->pid))
                              : node->imagePath)
      << "</span>";
  for (const auto &cat : node->categories) {
    out << "<span class=\"chip cat-" << HtmlEscape(cat) << "\">"
        << HtmlEscape(cat) << "</span>";
  }
  out << "<span class=\"count\">" << node->eventCount << "</span>";
  out << "</div>";
  if (!node->children.empty()) {
    out << "<ul>";
    for (const auto *child : node->children) EmitProcessNode(out, child);
    out << "</ul>";
  }
  out << "</li>";
}

std::string EmitProcessTreeHtml(const ProcessForest &forest) {
  std::ostringstream out;
  out << "<ul class=\"proc-tree\">";
  for (const auto *root : forest.roots) EmitProcessNode(out, root);
  out << "</ul>";
  return out.str();
}

// ----- Analyst-grade grouped sections (Any.Run-style) ------------------
//
// These render ABOVE the full event timeline. Each emitter is self-contained
// and renders nothing (returns "did it draw anything?") when it has no rows, so
// the caller can skip the surrounding section card. Every untrusted string runs
// through HtmlEscape, matching the rest of this renderer.

constexpr int kProcessTreeMaxDepth = 64; // cycle/abuse guard for BuildProcessTree

// Truncate a command line for the visible cell; the full value goes in title=.
std::string TruncateForCell(const std::string &text, size_t max = 120) {
  if (text.size() <= max) return text;
  return text.substr(0, max) + "…";
}

// Look up a detail key, returning "" when absent.
std::string Detail(const EventRecord &e, const char *key) {
  const auto it = e.details.find(key);
  return it == e.details.end() ? std::string() : it->second;
}

bool ActionIs(const EventRecord &e, const char *suffix) {
  return e.action == suffix || e.action.find(suffix) != std::string::npos;
}

} // namespace

std::vector<ProcessTreeNode> BuildProcessTree(
    const std::vector<EventRecord> &events) {
  // 1) Collapse process.start events into per-PID node records. A PID may
  // appear more than once (e.g. start then later detail) -- first start wins for
  // identity, but we still let a later record fill an empty field.
  std::map<uint32_t, ProcessTreeNode> nodes;
  std::map<uint32_t, std::vector<uint32_t>> children; // parent -> child pids (ordered by map insert below)
  for (const auto &e : events) {
    const bool isStart = e.category == "process" && ActionIs(e, "process.start");
    if (!isStart) continue;
    auto &node = nodes[e.processId];
    node.processId = e.processId;
    if (node.parentProcessId == 0 && e.parentProcessId != 0) {
      node.parentProcessId = e.parentProcessId;
    }
    if (node.imagePath.empty() && !e.imagePath.empty()) node.imagePath = e.imagePath;
    if (node.commandLine.empty() && !e.commandLine.empty()) {
      node.commandLine = e.commandLine;
    }
    if (node.integrityLevel.empty() && !e.integrityLevel.empty()) {
      node.integrityLevel = e.integrityLevel;
    }
    if (node.userName.empty() && !e.userName.empty()) node.userName = e.userName;
    // A start event can already carry an exit code detail (e.g. short-lived
    // processes summarized in one record).
    if (!node.exited) {
      const auto exit = Detail(e, "exitCode");
      if (!exit.empty()) {
        node.exitCode = exit;
        node.exited = true;
      }
    }
  }
  if (nodes.empty()) return {};

  // 2) Fold in exit codes from process.stop events.
  for (const auto &e : events) {
    const bool isStop = e.category == "process" && ActionIs(e, "process.stop");
    if (!isStop) continue;
    const auto it = nodes.find(e.processId);
    if (it == nodes.end()) continue;
    it->second.exited = true;
    auto exit = Detail(e, "exitCode");
    if (exit.empty()) exit = Detail(e, "exit");
    if (!exit.empty()) it->second.exitCode = exit;
  }

  // 3) Wire parent->children. A node whose parent isn't a known process becomes
  // a root. std::map keeps both the node set and each child list in ascending
  // PID order, giving a deterministic traversal.
  std::vector<uint32_t> roots;
  for (auto &[pid, node] : nodes) {
    if (node.parentProcessId != 0 && nodes.count(node.parentProcessId) &&
        node.parentProcessId != pid) {
      children[node.parentProcessId].push_back(pid);
    } else {
      roots.push_back(pid);
    }
  }

  // 4) Depth-first flatten with a visited set (cycle guard) + a hard depth cap.
  // A pid reachable via a cycle is only emitted once; the cap bounds runaway
  // chains. Both guards guarantee termination on adversarial telemetry.
  std::vector<ProcessTreeNode> out;
  std::set<uint32_t> visited;
  std::function<void(uint32_t, int)> walk = [&](uint32_t pid, int depth) {
    if (depth > kProcessTreeMaxDepth) return;
    if (!visited.insert(pid).second) return; // already emitted -> break cycle
    auto it = nodes.find(pid);
    if (it == nodes.end()) return;
    ProcessTreeNode node = it->second;
    node.depth = depth;
    out.push_back(node);
    const auto kids = children.find(pid);
    if (kids != children.end()) {
      for (uint32_t child : kids->second) walk(child, depth + 1);
    }
  };
  for (uint32_t pid : roots) walk(pid, 0);
  // Safety net: any node not reached from a root (only possible if every path
  // into it was a pure cycle) is emitted as a depth-0 orphan so it never
  // silently vanishes from the report.
  for (auto &[pid, node] : nodes) {
    if (!visited.count(pid)) {
      ProcessTreeNode orphan = node;
      orphan.depth = 0;
      visited.insert(pid);
      out.push_back(orphan);
    }
  }
  return out;
}

namespace {

// Returns true if it rendered any rows.
bool EmitProcessTreeSection(std::ostringstream &html,
                            const std::vector<EventRecord> &events) {
  const auto tree = BuildProcessTree(events);
  if (tree.empty()) return false;
  // Highlight nodes whose parent->this lineage is a suspicious chain (maldoc
  // execution, proxy-exec, ...) -- the Any.Run "malicious process" highlight.
  auto baseLower = [](std::string s) {
    const size_t sl = s.find_last_of("\\/");
    if (sl != std::string::npos) s = s.substr(sl + 1);
    for (char &c : s) c = static_cast<char>(std::tolower((unsigned char)c));
    return s;
  };
  std::map<std::string, ProcessChainHit> chainByPair;
  for (const auto &h : ClassifyProcessChains(events)) {
    chainByPair[h.parent + "|" + h.child] = h;
  }
  std::map<uint32_t, std::string> imgByPid;
  for (const auto &n : tree) imgByPid[n.processId] = n.imagePath;
  html << "<ul class=\"proc-exec-tree\">";
  for (const auto &node : tree) {
    const int indent = node.depth * 18; // px per nesting level
    html << "<li class=\"proc-exec\" style=\"margin-left:" << indent
         << "px\" data-pid=\"" << node.processId << "\">";
    html << "<span class=\"pid\">" << node.processId << "</span>";
    html << "<span class=\"name\">"
         << HtmlEscape(node.imagePath.empty()
                           ? ("pid " + std::to_string(node.processId))
                           : node.imagePath)
         << "</span>";
    {
      const auto pit = imgByPid.find(node.parentProcessId);
      if (pit != imgByPid.end()) {
        const auto cit = chainByPair.find(baseLower(pit->second) + "|" +
                                          baseLower(node.imagePath));
        if (cit != chainByPair.end()) {
          html << "<span class=\"chip\" style=\"background:var(--bad);color:#fff\""
                  " title=\""
               << HtmlEscape(cit->second.reason) << "\">&#9888; suspicious spawn ("
               << HtmlEscape(cit->second.mitre) << ")</span>";
        }
      }
    }
    if (node.exited) {
      html << "<span class=\"chip exit\">exit "
           << HtmlEscape(node.exitCode.empty() ? "?" : node.exitCode)
           << "</span>";
    }
    if (!node.integrityLevel.empty()) {
      html << "<span class=\"chip integ\">" << HtmlEscape(node.integrityLevel)
           << "</span>";
    }
    if (!node.userName.empty()) {
      html << "<span class=\"who mono\">" << HtmlEscape(node.userName)
           << "</span>";
    }
    if (!node.commandLine.empty()) {
      html << "<div class=\"cmd mono\" title=\"" << HtmlEscape(node.commandLine)
           << "\">" << HtmlEscape(TruncateForCell(node.commandLine));
      const CommandLineThreat clt = ClassifyCommandLine(node.commandLine);
      if (clt.suspicious) {
        html << " <span style=\"color:var(--bad)\">&#9888; " << HtmlEscape(clt.reason)
             << " (" << HtmlEscape(clt.technique) << ")</span>";
      }
      html << "</div>";
    }
    html << "</li>";
  }
  html << "</ul>";
  return true;
}

bool EmitPersistenceSection(std::ostringstream &html,
                            const std::vector<EventRecord> &events) {
  bool any = false;
  std::ostringstream rows;
  for (const auto &e : events) {
    const bool isRegistry =
        e.category == "registry" || e.action.find("registry") != std::string::npos;
    const bool isFile =
        e.category == "file" &&
        (ActionIs(e, "file.create") || ActionIs(e, "file.modify"));
    if (!isRegistry && !isFile) continue;

    // Classify the mechanism from the raw target (recovers the autostart surface
    // the agent didn't pre-label), and prefer the event's own MITRE when set.
    const PersistenceMatch m = ClassifyPersistence(e.category, e.target);
    if (!m.matched && e.mitre.empty()) continue; // not a persistence write
    any = true;
    const std::string mitre = !e.mitre.empty() ? e.mitre : m.mitre;
    const std::string name = MitreTechniqueName(mitre);
    std::string techCell = HtmlEscape(mitre);
    if (!name.empty()) {
      const auto pos = name.rfind(": ");
      techCell += " <span style=\"opacity:.7\">" +
                  HtmlEscape(pos == std::string::npos ? name : name.substr(pos + 2)) +
                  "</span>";
    }
    rows << "<tr><td class=\"mono\">"
         << HtmlEscape(m.matched ? m.mechanism : "registry autostart")
         << "</td><td class=\"mono\">" << techCell
         << "</td><td class=\"mono\" title=\"" << HtmlEscape(e.target) << "\">"
         << HtmlEscape(TruncateForCell(e.target)) << "</td><td class=\"mono\">"
         << HtmlEscape(Detail(e, "data")) << "</td></tr>";
  }
  if (!any) return false;
  html << "<table><thead><tr><th>Mechanism</th><th>Technique</th>"
          "<th>Key / Value / Path</th><th>Data</th></tr></thead><tbody>"
       << rows.str() << "</tbody></table>";
  return true;
}

bool EmitDroppedFilesSection(std::ostringstream &html,
                             const std::vector<EventRecord> &events) {
  bool any = false;
  std::ostringstream rows;
  for (const auto &e : events) {
    const bool isDrop = e.category == "file" &&
                        (ActionIs(e, "file.create") || ActionIs(e, "file.modify"));
    if (!isDrop) continue;
    any = true;
    const std::string fileType = Detail(e, "fileType");
    const std::string sha256 = Detail(e, "sha256");
    std::string shaCell;
    if (!sha256.empty()) {
      const std::string shaShort =
          sha256.size() > 16 ? sha256.substr(0, 16) + "…" : sha256;
      shaCell = "<span title=\"" + HtmlEscape(sha256) + "\">" +
                HtmlEscape(shaShort) + "</span>";
    } else {
      const std::string skipped = Detail(e, "hashSkipped");
      shaCell = HtmlEscape(skipped.empty() ? "" : ("(skipped: " + skipped + ")"));
    }
    rows << "<tr><td class=\"mono\" title=\"" << HtmlEscape(e.target)
         << "\">" << HtmlEscape(TruncateForCell(e.target))
         << "</td><td class=\"mono\">" << HtmlEscape(fileType)
         << "</td><td class=\"mono\">" << HtmlEscape(Detail(e, "size"))
         << "</td><td class=\"mono\">" << shaCell << "</td></tr>";
  }
  if (!any) return false;
  html << "<table><thead><tr><th>Path</th><th>Type</th><th>Size</th>"
          "<th>SHA-256</th></tr></thead><tbody>"
       << rows.str() << "</tbody></table>";
  return true;
}

bool EmitNetworkSection(std::ostringstream &html,
                        const std::vector<EventRecord> &events) {
  bool any = false;
  std::ostringstream rows;
  for (const auto &e : events) {
    const bool isNet = e.category == "network" &&
                       (ActionIs(e, "network.connect") ||
                        ActionIs(e, "network.connection") ||
                        ActionIs(e, "network.close"));
    if (!isNet) continue;
    any = true;
    const std::string proc =
        (e.imagePath.empty() ? std::string("pid") : e.imagePath) + " (" +
        std::to_string(e.processId) + ")";
    std::string state = Detail(e, "state");
    if (state.empty()) state = e.action;
    const NetworkIndicator ni = ClassifyEndpoint(e.target);
    rows << "<tr><td class=\"mono\">" << HtmlEscape(proc)
         << "</td><td class=\"mono\">" << HtmlEscape(e.target)
         << "</td><td class=\"mono\">";
    if (!ni.service.empty()) rows << HtmlEscape(ni.service);
    if (ni.suspicious) {
      if (!ni.service.empty()) rows << " ";
      rows << "<span style=\"color:var(--bad)\">&#9888; " << HtmlEscape(ni.note)
           << "</span>";
    }
    rows << "</td><td class=\"mono\">" << HtmlEscape(state) << "</td></tr>";
  }
  if (!any) return false;
  html << "<table><thead><tr><th>Process</th><th>Remote</th>"
          "<th>Service</th><th>State</th></tr></thead><tbody>"
       << rows.str() << "</tbody></table>";
  return true;
}

bool EmitCrashesSection(std::ostringstream &html,
                        const std::vector<EventRecord> &events) {
  // Aggregate into distinct fault signatures (CrashSummary) instead of one row
  // per event -- a shell crash-loop is dozens of identical crashes, so the raw
  // list was pure noise. Each row is now count + app + exception (code + human
  // name) + faulting module/version/offset.
  const CrashSummary cs = SummarizeCrashes(events);
  if (cs.signatures.empty()) return false;
  html << "<p style=\"opacity:.7;margin:0 0 6px\">" << cs.totalCrashes
       << " crash event(s), " << cs.signatures.size()
       << " distinct signature(s)</p>";
  html << "<table><thead><tr><th>#</th><th>App</th><th>Exception</th>"
          "<th>Module</th><th>Offset</th></tr></thead><tbody>";
  for (const auto &s : cs.signatures) {
    std::string exc = s.exceptionCode;
    if (!s.exceptionName.empty()) exc += " (" + s.exceptionName + ")";
    std::string mod = s.module;
    if (!s.moduleVersion.empty()) mod += " v" + s.moduleVersion;
    html << "<tr><td class=\"mono\">" << s.count << "</td><td class=\"mono\">"
         << HtmlEscape(s.image) << "</td><td class=\"mono\">" << HtmlEscape(exc)
         << "</td><td class=\"mono\">" << HtmlEscape(mod)
         << "</td><td class=\"mono\">" << HtmlEscape(s.offset) << "</td></tr>";
  }
  html << "</tbody></table>";
  return true;
}

// Module Loads (image/DLL-load telemetry). Suspicious side-loaded /
// search-order-hijacked DLLs (details["suspicion"] set / MITRE-tagged) are
// listed FIRST and highlighted; a bounded tail of normal loads follows so the
// section stays readable on a process that pulls in hundreds of system DLLs.
bool EmitModuleLoadsSection(std::ostringstream &html,
                            const std::vector<EventRecord> &events) {
  constexpr size_t kNormalLoadCap = 64;
  std::ostringstream suspRows;
  std::ostringstream normalRows;
  size_t suspCount = 0;
  size_t normalShown = 0;
  size_t normalTotal = 0;
  for (const auto &e : events) {
    if (e.category != "image" || !ActionIs(e, "image.load")) continue;
    const bool suspicious =
        !e.mitre.empty() || !Detail(e, "suspicion").empty();
    const std::string loader =
        (e.imagePath.empty() ? std::string("pid") : e.imagePath) + " (" +
        std::to_string(e.processId) + ")";
    if (suspicious) {
      ++suspCount;
      suspRows << "<tr class=\"bad\"><td class=\"mono\">"
               << HtmlEscape(e.mitre.empty() ? "(hijack)" : e.mitre)
               << "</td><td class=\"mono\" title=\"" << HtmlEscape(e.target)
               << "\">" << HtmlEscape(TruncateForCell(e.target))
               << "</td><td class=\"mono\">" << HtmlEscape(loader)
               << "</td></tr>";
    } else {
      ++normalTotal;
      if (normalShown < kNormalLoadCap) {
        ++normalShown;
        normalRows << "<tr><td class=\"mono\" title=\"" << HtmlEscape(e.target)
                   << "\">" << HtmlEscape(TruncateForCell(e.target))
                   << "</td><td class=\"mono\">" << HtmlEscape(loader)
                   << "</td></tr>";
      }
    }
  }
  if (suspCount == 0 && normalTotal == 0) return false;

  if (suspCount > 0) {
    html << "<h3 class=\"bad\">Side-loaded / hijacked modules (" << suspCount
         << ")</h3>";
    html << "<table><thead><tr><th>Technique</th><th>Module</th>"
            "<th>Loaded by</th></tr></thead><tbody>"
         << suspRows.str() << "</tbody></table>";
  }
  if (normalTotal > 0) {
    html << "<h3>Other module loads (" << normalTotal << ")</h3>";
    html << "<table><thead><tr><th>Module</th><th>Loaded by</th></tr></thead>"
            "<tbody>"
         << normalRows.str() << "</tbody></table>";
    if (normalTotal > normalShown) {
      html << "<div class=\"muted\">… " << (normalTotal - normalShown)
           << " more normal load(s) not shown.</div>";
    }
  }
  return true;
}

bool EmitMitreChips(std::ostringstream &html,
                    const std::vector<std::string> &techniques) {
  if (techniques.empty()) return false;
  html << "<div class=\"mitre-chips\">";
  for (const auto &t : techniques) {
    if (t.empty()) continue;
    const std::string name = MitreTechniqueName(t);
    html << "<span class=\"tag capability\"";
    if (!name.empty()) html << " title=\"" << HtmlEscape(name) << "\"";
    html << ">" << HtmlEscape(t);
    if (!name.empty()) {
      // Short inline label: the sub-technique part (after the last ": "), or the
      // whole name for a base technique. Full name is in the hover title.
      const auto pos = name.rfind(": ");
      const std::string shortName =
          (pos == std::string::npos) ? name : name.substr(pos + 2);
      html << " <span style=\"opacity:.7\">" << HtmlEscape(shortName)
           << "</span>";
    }
    html << "</span>";
  }
  html << "</div>";
  return true;
}

// ATT&CK matrix-style view: the techniques grouped by tactic in canonical
// kill-chain order (Any.Run presents the chain this way). Each non-empty tactic
// becomes a labeled row of chips.
bool EmitMitreByTactic(std::ostringstream &html,
                       const std::vector<std::string> &techniques) {
  if (techniques.empty()) return false;
  static const char *kOrder[] = {
      "Initial Access",   "Execution",        "Persistence",
      "Privilege Escalation", "Defense Evasion", "Credential Access",
      "Discovery",        "Lateral Movement", "Collection",
      "Command and Control", "Exfiltration",  "Impact", "Other"};
  std::map<std::string, std::vector<std::string>> byTactic;
  for (const auto &t : techniques)
    if (!t.empty()) byTactic[MitreTechniqueTactic(t)].push_back(t);
  for (const char *tac : kOrder) {
    const auto it = byTactic.find(tac);
    if (it == byTactic.end()) continue;
    html << "<div class=\"mitre-tactic\"><div class=\"mitre-tactic-h\">"
         << HtmlEscape(tac) << " <span style=\"opacity:.6\">("
         << it->second.size() << ")</span></div>";
    EmitMitreChips(html, it->second);
    html << "</div>";
  }
  return true;
}

const char *kStylesheet = R"CSS(
:root{
  --bg:#0f1620; --panel:#151e2a; --panel2:#1a2433; --border:#27344a;
  --text:#e7eef7; --muted:#8aa1bd; --accent:#3aa2ff; --bad:#f04b5e;
  --warn:#ffb13b; --good:#3ddc97; --tag:#2d4054;
}
*{box-sizing:border-box}
body{margin:0;font-family:Segoe UI,Inter,Arial,sans-serif;
     background:var(--bg);color:var(--text)}
header{display:flex;align-items:center;gap:18px;padding:18px 24px;
       background:var(--panel);border-bottom:1px solid var(--border);
       position:sticky;top:0;z-index:5}
header .icon{width:48px;height:48px;border-radius:8px;background:#243245;
             display:flex;align-items:center;justify-content:center;
             font-size:22px}
header h1{margin:0;font-size:18px;font-weight:600}
header .sub{color:var(--muted);font-size:13px;font-family:Consolas,monospace}
header .tags{margin-left:auto;display:flex;gap:6px;flex-wrap:wrap}
.banner.malicious{background:linear-gradient(90deg,#54121b,#1a0a0e);
                  color:#ffd0d6;padding:8px 24px;font-size:13px;
                  border-bottom:1px solid #6a1c27}
.banner.suspicious{background:linear-gradient(90deg,#3d2a07,#1a1308);
                   color:#ffe6b8;padding:8px 24px;font-size:13px;
                   border-bottom:1px solid #5a4416}
.banner.clean{background:linear-gradient(90deg,#0b3923,#0c1b13);
              color:#cdf3df;padding:8px 24px;font-size:13px;
              border-bottom:1px solid #1a5635}
.banner.error{background:linear-gradient(90deg,#343944,#15181f);
              color:#d8e1ee;padding:8px 24px;font-size:13px;
              border-bottom:1px solid #515a69}
main{display:grid;grid-template-columns:280px 1fr 320px;gap:14px;padding:14px}
section.panel{background:var(--panel);border:1px solid var(--border);
              border-radius:8px;padding:14px;min-height:160px}
section.panel h2{margin:0 0 10px;font-size:13px;letter-spacing:1px;
                 text-transform:uppercase;color:var(--muted)}
.tag{display:inline-block;background:var(--tag);color:#cfe1f6;
     border:1px solid var(--border);padding:3px 8px;border-radius:12px;
     font-size:12px;letter-spacing:.3px}
.tag.family{background:#5a2230;color:#ffd6df;border-color:#82394a}
.tag.packer{background:#3f3320;color:#ffe1b3;border-color:#6a543a}
.tag.capability{background:#1f3a52;color:#bedaf6;border-color:#34577a}
.tag.language{background:#1f3f32;color:#bce5cf;border-color:#356a52}
.tag.obfuscator{background:#3a204f;color:#dcc8ff;border-color:#5b3789}
.badge{display:inline-block;padding:3px 10px;border-radius:10px;
       font-size:11px;font-weight:600;letter-spacing:.6px}
.badge.malicious{background:var(--bad);color:#fff}
.badge.suspicious{background:var(--warn);color:#1a1308}
.badge.clean{background:var(--good);color:#0c1b13}
.badge.error{background:#555;color:#fff}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:6px 8px;text-align:left;border-bottom:1px solid var(--border);
      vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;
   letter-spacing:.4px}
tr:hover td{background:rgba(58,162,255,.06)}
.kv{display:grid;grid-template-columns:90px 1fr;gap:6px 12px;font-size:13px}
.kv .k{color:var(--muted)}
ul.why{margin:2px 0;padding-left:16px;font-size:12px;color:var(--muted)}
ul.why li{margin:2px 0}
code,.mono{font-family:Consolas,Cascadia Code,monospace;font-size:12px;
            color:#9ccfff}
.proc-tree{list-style:none;padding-left:0;margin:0}
.proc-tree ul{list-style:none;padding-left:14px;margin:2px 0 4px;
              border-left:1px dashed var(--border)}
.proc-row{display:flex;align-items:center;gap:6px;padding:5px 6px;
          border-radius:6px;cursor:pointer}
.proc-row:hover{background:#243245}
.proc-row .pid{font-family:Consolas,monospace;color:var(--muted);
               min-width:40px;text-align:right}
.proc-row .name{flex:1;overflow:hidden;text-overflow:ellipsis;
                white-space:nowrap}
.proc-row .count{color:var(--muted);font-size:11px}
.chip{display:inline-block;font-size:10px;padding:1px 6px;border-radius:8px;
      background:#243245;color:#cfdcf0;text-transform:uppercase;letter-spacing:.4px}
.chip.cat-file{background:#1f3a52}
.chip.cat-registry{background:#3f3320}
.chip.cat-network{background:#1f3f32}
.chip.cat-process{background:#3a204f}
.toolbar{display:flex;gap:8px;align-items:center;margin-bottom:8px}
.toolbar input{flex:1;background:var(--panel2);color:var(--text);
               border:1px solid var(--border);border-radius:6px;
               padding:5px 9px;font-size:13px}
.toolbar select{background:var(--panel2);color:var(--text);
                border:1px solid var(--border);border-radius:6px;
                padding:5px 7px;font-size:13px}
.ioc-list{margin:0;padding:0;list-style:none;font-size:12px;
          max-height:260px;overflow:auto}
.ioc-list li{padding:3px 0;border-bottom:1px dashed var(--border);
             font-family:Consolas,monospace;word-break:break-all}
.detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media (max-width: 1200px){main{grid-template-columns:1fr}}
.filmstrip{display:flex;gap:6px;overflow-x:auto;padding:6px 0}
.filmstrip img{height:108px;border-radius:4px;border:1px solid var(--border);
               cursor:pointer}
#screenshot-hero{width:100%;max-height:380px;object-fit:contain;
                 background:#000;border:1px solid var(--border);border-radius:6px}
.empty{color:var(--muted);font-style:italic;font-size:13px}
.section-card{background:var(--panel2);border:1px solid var(--border);
              border-radius:8px;padding:12px 14px;margin:0 0 14px}
.section-card h2{margin:0 0 10px}
.proc-exec-tree{list-style:none;padding:0;margin:0}
.proc-exec{padding:6px 8px;border-left:2px solid var(--border);
           border-radius:0 6px 6px 0;margin:3px 0;background:rgba(58,162,255,.04)}
.proc-exec .pid{font-family:Consolas,monospace;color:var(--muted);
                margin-right:8px}
.proc-exec .name{font-weight:600}
.proc-exec .who{color:var(--muted);margin-left:8px}
.proc-exec .cmd{color:#9ccfff;margin-top:3px;word-break:break-all}
.chip.exit{background:#3f2330;color:#ffd6df}
.chip.integ{background:#243245;color:#cfe1f6}
.mitre-chips{display:flex;gap:6px;flex-wrap:wrap}
.mitre-tactic{margin:6px 0}
.mitre-tactic-h{font-size:12px;font-weight:600;color:var(--accent);margin:4px 0 3px}
h3.bad{color:var(--bad);margin:10px 0 6px}
tr.bad td{background:rgba(240,75,94,.10);color:#ffd0d6}
.muted{color:var(--muted);font-size:12px;margin-top:4px}
)CSS";

const char *kJs = R"JS(
const AntiMal = {
  pidFilter: null,
  searchTerm: "",
  filterByPid(pid){
    AntiMal.pidFilter = AntiMal.pidFilter === pid ? null : pid;
    AntiMal.applyFilters();
  },
  applyFilters(){
    const term = AntiMal.searchTerm.toLowerCase();
    document.querySelectorAll("#event-tbody tr").forEach(tr => {
      const pid = parseInt(tr.dataset.pid, 10);
      const text = (tr.dataset.search || "").toLowerCase();
      const pidOk = !AntiMal.pidFilter || pid === AntiMal.pidFilter;
      const txtOk = !term || text.includes(term);
      tr.style.display = (pidOk && txtOk) ? "" : "none";
    });
    document.querySelectorAll(".proc-row").forEach(r => {
      const li = r.closest("li");
      if (!li) return;
      const pid = parseInt(li.dataset.pid, 10);
      li.style.outline = (AntiMal.pidFilter === pid) ? "1px solid #3aa2ff" : "";
    });
    document.getElementById("filter-status").textContent =
      AntiMal.pidFilter ? "filtered to pid " + AntiMal.pidFilter
                        : (term ? "search: " + term : "all events");
  },
  search(value){ AntiMal.searchTerm = value || ""; AntiMal.applyFilters(); },
  showFrame(idx){
    const frames = document.querySelectorAll("#filmstrip img");
    if (!frames.length) return;
    const i = Math.max(0, Math.min(frames.length - 1, idx));
    document.getElementById("screenshot-hero").src = frames[i].src;
    document.getElementById("frame-index").textContent =
      (i + 1) + " / " + frames.length;
  },
  // Defang IOCs so the (shareable) report is safe to forward without an
  // accidental click. Display-only; textContent keeps it injection-safe.
  defang(s){
    return String(s).replace(/https:\/\//g,"hxxps://").replace(/http:\/\//g,"hxxp://")
      .replace(/ftp:\/\//g,"fxp://").replace(/\./g,"[.]").replace(/@/g,"[@]");
  },
  setDefang(on){
    document.querySelectorAll(".ioc-list li").forEach(li => {
      if (li.dataset.live === undefined) li.dataset.live = li.textContent;
      li.textContent = on ? AntiMal.defang(li.dataset.live) : li.dataset.live;
    });
  },
};
document.addEventListener("DOMContentLoaded", () => {
  const search = document.getElementById("event-search");
  if (search) search.addEventListener("input", e => AntiMal.search(e.target.value));
  const dfg = document.getElementById("defang-toggle");
  if (dfg) dfg.addEventListener("change", e => AntiMal.setDefang(e.target.checked));
  const filmstrip = document.getElementById("filmstrip");
  if (filmstrip) {
    filmstrip.addEventListener("mousemove", e => {
      const r = filmstrip.getBoundingClientRect();
      const ratio = (e.clientX - r.left) / r.width;
      const frames = filmstrip.querySelectorAll("img");
      AntiMal.showFrame(Math.floor(ratio * frames.length));
    });
    if (filmstrip.querySelector("img")) AntiMal.showFrame(0);
  }
});
)JS";

void EmitTags(std::ostringstream &html, const std::vector<ScanTag> &tags) {
  for (const auto &tag : tags) {
    html << "<span class=\"tag " << HtmlEscape(tag.category) << "\">"
         << HtmlEscape(tag.tag);
    if (tag.confidence > 0) {
      html << " <span class=\"mono\" style=\"opacity:.7\">"
           << tag.confidence << "</span>";
    }
    html << "</span>";
  }
}

void EmitIocList(std::ostringstream &html, const std::vector<std::string> &items,
                 const std::string &emptyMessage) {
  if (items.empty()) {
    html << "<div class=\"empty\">" << HtmlEscape(emptyMessage) << "</div>";
    return;
  }
  html << "<ul class=\"ioc-list\">";
  for (const auto &item : items) {
    html << "<li>" << HtmlEscape(item) << "</li>";
  }
  html << "</ul>";
}

void EmitEventTable(std::ostringstream &html,
                    const std::vector<EventRecord> &events) {
  html << "<div class=\"toolbar\">";
  html << "<input id=\"event-search\" placeholder=\"Search events (path, action, target)\">";
  html << "<span id=\"filter-status\" class=\"mono\" style=\"color:var(--muted)\">all events</span>";
  html << "</div>";
  html << "<table><thead><tr><th>Time</th><th>PID</th><th>Source</th><th>Category</th><th>Action</th><th>Target</th><th>Type</th><th>SHA-256</th><th>User</th><th>Integ.</th><th>Cmd / Exit</th><th>MITRE</th></tr></thead>";
  html << "<tbody id=\"event-tbody\">";
  // Anchor for relative timeline offsets = the earliest parseable event time.
  int64_t anchorEpoch = -1;
  for (const auto &e : events) {
    const int64_t ep = ParseIso8601ToEpochSeconds(e.timestampUtc);
    if (ep >= 0 && (anchorEpoch < 0 || ep < anchorEpoch)) anchorEpoch = ep;
  }
  for (const auto &e : events) {
    // Prefer the command line; fall back to the exit code (rendered in hex by
    // the collector) so a crashing process shows e.g. 0xC0000409 here.
    std::string cmdOrExit = e.commandLine;
    if (cmdOrExit.empty()) {
      const auto it = e.details.find("exitCode");
      if (it != e.details.end()) {
        cmdOrExit = "exit " + it->second;
      }
    }
    // Dropped-file enrichment: the in-guest collector tags file.create /
    // file.modify events with the file's magic-byte type + sha256 (or a skip
    // marker when it couldn't read/hash the file). Show the type, and a short
    // sha256 with the full hash in a tooltip.
    std::string fileType;
    if (const auto it = e.details.find("fileType"); it != e.details.end()) {
      fileType = it->second;
    }
    std::string sha256;
    if (const auto it = e.details.find("sha256"); it != e.details.end()) {
      sha256 = it->second;
    }
    std::string shaShort = sha256.size() > 16 ? sha256.substr(0, 16) + "…"
                                              : sha256;
    if (sha256.empty()) {
      if (const auto it = e.details.find("hashSkipped"); it != e.details.end()) {
        shaShort = "(" + it->second + ")";  // size | locked | rate
      }
    }
    const std::string search = e.imagePath + " " + e.fullImagePath + " " +
                               e.action + " " + e.target + " " + e.commandLine +
                               " " + e.userName + " " + fileType + " " + sha256;
    const std::string relLabel =
        RelativeTimeLabel(ParseIso8601ToEpochSeconds(e.timestampUtc), anchorEpoch);
    html << "<tr data-pid=\"" << e.processId << "\" data-search=\""
         << HtmlEscape(search) << "\">"
         << "<td class=\"mono\">" << HtmlEscape(e.timestampUtc);
    if (!relLabel.empty()) {
      html << "<br><span style=\"color:var(--muted)\">" << HtmlEscape(relLabel)
           << "</span>";
    }
    html << "</td>"
         << "<td class=\"mono\">" << e.processId << "</td>"
         << "<td>" << HtmlEscape(e.source) << "</td>"
         << "<td><span class=\"chip cat-" << HtmlEscape(e.category) << "\">"
         << HtmlEscape(e.category) << "</span></td>"
         << "<td>" << HtmlEscape(e.action) << "</td>"
         << "<td class=\"mono\" title=\"" << HtmlEscape(e.fullImagePath)
         << "\">" << HtmlEscape(e.target) << "</td>"
         << "<td class=\"mono\">" << HtmlEscape(fileType) << "</td>"
         << "<td class=\"mono\" title=\"" << HtmlEscape(sha256) << "\">"
         << HtmlEscape(shaShort) << "</td>"
         << "<td class=\"mono\">" << HtmlEscape(e.userName) << "</td>"
         << "<td class=\"mono\">" << HtmlEscape(e.integrityLevel) << "</td>"
         << "<td class=\"mono\" title=\"" << HtmlEscape(e.commandLine) << "\">"
         << HtmlEscape(cmdOrExit) << "</td>"
         << "<td class=\"mono\">" << HtmlEscape(e.mitre) << "</td></tr>";
  }
  html << "</tbody></table>";
  if (events.empty()) {
    html << "<div class=\"empty\" style=\"margin-top:12px\">No dynamic events recorded for this run.</div>";
  }
}

void EmitFilmstrip(std::ostringstream &html,
                   const std::vector<std::filesystem::path> &frames) {
  if (frames.empty()) {
    html << "<div class=\"empty\">No screenshots captured.</div>";
    return;
  }
  html << "<img id=\"screenshot-hero\" alt=\"current frame\">";
  html << "<div style=\"display:flex;justify-content:space-between;align-items:center;margin:4px 0\">";
  html << "<span class=\"mono\" style=\"color:var(--muted)\">Move the mouse across the strip to scrub through the run.</span>";
  html << "<span id=\"frame-index\" class=\"mono\" style=\"color:var(--muted)\">1 / " << frames.size() << "</span>";
  html << "</div>";
  html << "<div id=\"filmstrip\" class=\"filmstrip\">";
  for (const auto &frame : frames) {
    const auto src = frame.is_absolute()
                         ? std::filesystem::path("screenshots") / frame.filename()
                         : frame;
    html << "<img src=\"" << HtmlEscape(HtmlPath(src)) << "\">";
  }
  html << "</div>";
}

bool IsGuestFramePath(const std::filesystem::path &frame) {
  const auto name = ToLowerAscii(frame.filename().string());
  return name.rfind("guest-", 0) == 0;
}

std::vector<std::filesystem::path> PreferGuestFrames(
    std::vector<std::filesystem::path> frames) {
  std::sort(frames.begin(), frames.end());
  std::vector<std::filesystem::path> guestFrames;
  for (const auto &frame : frames) {
    if (IsGuestFramePath(frame)) {
      guestFrames.push_back(frame);
    }
  }
  return guestFrames.empty() ? frames : guestFrames;
}

// ----- Discovering screenshot frames in the run directory --------------

std::vector<std::filesystem::path> DiscoverFramesNextTo(
    const std::filesystem::path &reportPath) {
  std::vector<std::filesystem::path> frames;
  std::error_code ec;
  const auto runDir = reportPath.parent_path();
  if (runDir.empty()) return frames;
  const auto framesDir = runDir / "screenshots";
  std::filesystem::directory_iterator it(framesDir, ec);
  std::filesystem::directory_iterator end;
  while (!ec && it != end) {
    if (it->is_regular_file(ec) &&
        ToLowerAscii(it->path().extension().string()) == ".png") {
      const auto frame =
          std::filesystem::path("screenshots") / it->path().filename();
      frames.push_back(frame);
    }
    it.increment(ec);
  }
  return PreferGuestFrames(frames);
}

} // namespace

std::string HtmlEscape(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (char c : text) {
    switch (c) {
    case '&':
      out += "&amp;";
      break;
    case '<':
      out += "&lt;";
      break;
    case '>':
      out += "&gt;";
      break;
    case '"':
      out += "&quot;";
      break;
    case '\'':
      out += "&#39;";
      break;
    default:
      out += c;
      break;
    }
  }
  return out;
}

std::string BuildHtmlReport(const AnalysisReport &report) {
  return BuildHtmlReportWithFrames(report, {});
}

std::string BuildHtmlReportWithFrames(const AnalysisReport &report,
                                      const std::vector<std::filesystem::path> &frames) {
  const auto displayFrames = PreferGuestFrames(frames);
  const auto &scan = report.scannerVerdict;
  const auto worst = scan.verdict == Verdict::Malicious || report.sandboxVerdict == Verdict::Malicious
                         ? Verdict::Malicious
                     : scan.verdict == Verdict::Suspicious || report.sandboxVerdict == Verdict::Suspicious
                         ? Verdict::Suspicious
                     : scan.verdict == Verdict::Error || report.sandboxVerdict == Verdict::Error
                         ? Verdict::Error
                         : Verdict::Clean;

  std::ostringstream html;
  html << "<!doctype html><html><head><meta charset=\"utf-8\">";
  html << "<title>AntiMal " << HtmlEscape(report.runId) << "</title>";
  html << "<style>" << kStylesheet << "</style></head><body>";

  // Header
  html << "<header><div class=\"icon\">AM</div><div><h1>"
       << HtmlEscape(PathToUtf8(report.samplePath.empty() ? scan.path : report.samplePath))
       << "</h1><div class=\"sub\">SHA-256 " << HtmlEscape(scan.sha256);
  if (!scan.sha1.empty()) {
    html << " &nbsp;&middot;&nbsp; SHA-1 " << HtmlEscape(scan.sha1);
  }
  if (!scan.md5.empty()) {
    html << " &nbsp;&middot;&nbsp; MD5 " << HtmlEscape(scan.md5);
  }
  if (!scan.imphash.empty()) {
    html << " &nbsp;&middot;&nbsp; imphash " << HtmlEscape(scan.imphash);
  }
  if (!scan.ctph.empty()) {
    html << " &nbsp;&middot;&nbsp; ctph " << HtmlEscape(scan.ctph);
  }
  html << " &nbsp;&middot;&nbsp; run " << HtmlEscape(report.runId) << "</div></div>";
  html << "<div class=\"tags\">";
  EmitTags(html, scan.tags);
  html << "</div></header>";

  // Verdict banner
  const std::string banner =
      worst == Verdict::Malicious  ? "Malicious activity detected"
      : worst == Verdict::Suspicious ? "Suspicious activity detected"
      : worst == Verdict::Error      ? "Dynamic analysis unavailable or blocked"
                                     : "No high-confidence threats detected";
  html << "<div class=\"banner " << HtmlEscape(ToString(worst)) << "\">"
       << HtmlEscape(banner) << "</div>";

  html << "<main>";

  // Left rail: process tree + tags + verdict summary
  html << "<section class=\"panel\"><h2>Verdict</h2>";
  html << "<div class=\"kv\">";
  html << "<div class=\"k\">scanner</div><div><span class=\"badge "
       << HtmlEscape(ToString(scan.verdict)) << "\">"
       << HtmlEscape(ToString(scan.verdict)) << "</span> score " << scan.score
       << "</div>";
  html << "<div class=\"k\">sandbox</div><div><span class=\"badge "
       << HtmlEscape(ToString(report.sandboxVerdict)) << "\">"
       << HtmlEscape(ToString(report.sandboxVerdict)) << "</span>";
  if (report.verdictScore != 0 || !report.verdictRationale.empty()) {
    html << " score " << report.verdictScore;
  }
  html << "</div>";
  // T07: explainable verdict -- the per-signal "why this verdict" list directly
  // under the sandbox badge so the conclusion is never an unexplained label.
  if (!report.verdictRationale.empty()) {
    html << "<div class=\"k\">why this verdict</div><div><ul class=\"why\">";
    for (const auto &line : report.verdictRationale) {
      html << "<li>" << HtmlEscape(line) << "</li>";
    }
    html << "</ul></div>";
  }
  if (!report.dynamicSummary.status.empty() || report.dynamicSummary.started) {
    html << "<div class=\"k\">VM</div><div>"
         << HtmlEscape(report.dynamicSummary.status.empty()
                           ? "not started"
                           : report.dynamicSummary.status)
         << ", sample executed "
         << (report.dynamicSummary.sampleExecuted ? "yes" : "no")
         << ", guest agent "
         << (report.dynamicSummary.guestAgentConnected ? "connected" : "not connected")
         << "</div>";
    {
      const BootOutcome bo = ClassifyBootOutcome(report.dynamicSummary);
      html << "<div class=\"k\">boot outcome</div><div>"
           << HtmlEscape(bo.stage) << " &middot; " << HtmlEscape(bo.detail);
      if (!bo.remediation.empty()) {
        html << "<div class=\"mono\" style=\"color:var(--muted);margin-top:2px\">"
             << HtmlEscape(bo.remediation) << "</div>";
      }
      html << "</div>";
    }
    if (!report.dynamicSummary.bootStage.empty()) {
      html << "<div class=\"k\">boot stage</div><div class=\"mono\">"
           << HtmlEscape(report.dynamicSummary.bootStage) << "</div>";
    }
    {
      const UsabilityReport u =
          ClassifyUsability(report.dynamicSummary, report.events);
      html << "<div class=\"k\">desktop usability</div><div>" << HtmlEscape(u.overall);
      html << "<div class=\"mono\" style=\"color:var(--muted);margin-top:2px\">";
      for (size_t i = 0; i < u.dimensions.size(); ++i) {
        const auto &d = u.dimensions[i];
        const char *color = d.status == "ok"
                                ? "var(--good)"
                                : (d.status == "crash-loop" ? "var(--bad)"
                                   : d.status == "degraded" ? "var(--warn)"
                                                            : "var(--muted)");
        html << (i ? " &middot; " : "") << HtmlEscape(d.name) << ":<span style=\"color:"
             << color << "\">" << HtmlEscape(d.status) << "</span>";
      }
      html << "</div>";
      if (!u.remediation.empty()) {
        html << "<div class=\"mono\" style=\"color:var(--muted);margin-top:2px\">"
             << HtmlEscape(u.remediation) << "</div>";
      }
      html << "</div>";
    }
    if (!report.dynamicSummary.liveFramePacingSummary.empty()) {
      html << "<div class=\"k\">live display</div><div class=\"mono\">"
           << HtmlEscape(report.dynamicSummary.liveFramePacingSummary)
           << "</div>";
    }
    {
      // Honest network-mode note: hostonly/nat are not yet wired to real egress,
      // so don't let an analyst assume traffic was captured (network visibility
      // here comes from in-guest TCP-table telemetry, not packet capture).
      const NetworkMode nm = report.dynamicSummary.networkMode;
      html << "<div class=\"k\">network mode</div><div>" << HtmlEscape(ToString(nm));
      if (nm == NetworkMode::HostOnly || nm == NetworkMode::Nat) {
        html << " <span style=\"color:var(--warn)\">&#9888; not wired to real "
                "egress yet — visibility is in-guest TCP-table telemetry, not "
                "packet capture</span>";
      } else {
        html << " <span style=\"opacity:.7\">(no guest network)</span>";
      }
      html << "</div>";
    }
    if (!report.dynamicSummary.windowsKernelReadGateStatus.empty()) {
      html << "<div class=\"k\">kernel gate</div><div class=\"mono\">"
           << HtmlEscape(report.dynamicSummary.windowsKernelReadGateStatus)
           << "</div>";
    }
    if (!report.dynamicSummary.windowsKernelReadGateEvidence.empty()) {
      html << "<div class=\"k\">kernel evidence</div><div>"
           << HtmlEscape(report.dynamicSummary.windowsKernelReadGateEvidence)
           << "</div>";
    }
    if (!report.dynamicSummary.windowsKernelReadGateFirstTarget.empty()) {
      html << "<div class=\"k\">first kernel target</div><div class=\"mono\">"
           << HtmlEscape(report.dynamicSummary.windowsKernelReadGateFirstTarget)
           << "</div>";
    }
    if (!report.dynamicSummary.windowsUserModeGateStatus.empty()) {
      html << "<div class=\"k\">user-mode gate</div><div class=\"mono\">"
           << HtmlEscape(report.dynamicSummary.windowsUserModeGateStatus)
           << "</div>";
    }
    if (!report.dynamicSummary.windowsUserModeGateEvidence.empty()) {
      html << "<div class=\"k\">user-mode evidence</div><div>"
           << HtmlEscape(report.dynamicSummary.windowsUserModeGateEvidence)
           << "</div>";
    }
    if (!report.dynamicSummary.windowsUserModeGateFirstTarget.empty()) {
      html << "<div class=\"k\">first user-mode target</div><div class=\"mono\">"
           << HtmlEscape(report.dynamicSummary.windowsUserModeGateFirstTarget)
           << "</div>";
    }
    if (!report.dynamicSummary.bootFailureStatus.empty()) {
      html << "<div class=\"k\">boot failure</div><div class=\"mono\">"
           << HtmlEscape(report.dynamicSummary.bootFailureStatus);
      if (!report.dynamicSummary.bootFailureStatusName.empty()) {
        html << " " << HtmlEscape(report.dynamicSummary.bootFailureStatusName);
      }
      if (!report.dynamicSummary.bootFailureStatusSource.empty()) {
        html << " (" << HtmlEscape(report.dynamicSummary.bootFailureStatusSource)
             << ")";
      }
      html << "</div>";
    }
    if (!report.dynamicSummary.bootBlocker.empty()) {
      html << "<div class=\"k\">boot blocker</div><div>"
           << HtmlEscape(report.dynamicSummary.bootBlocker) << "</div>";
    }
    if (!report.dynamicSummary.bootContractSuspect.empty()) {
      html << "<div class=\"k\">boot contract suspect</div><div>"
           << HtmlEscape(report.dynamicSummary.bootContractSuspect) << "</div>";
    }
    if (!report.dynamicSummary.bootContractSuspectDetails.empty()) {
      html << "<div class=\"k\">boot contract details</div><div>"
           << HtmlEscape(report.dynamicSummary.bootContractSuspectDetails)
           << "</div>";
    }
    if (!report.dynamicSummary.ciPolicyInventory.empty()) {
      html << "<div class=\"k\">CI policy inventory</div><div class=\"mono\">"
           << HtmlEscape(report.dynamicSummary.ciPolicyInventory) << "</div>";
    }
    if (!report.dynamicSummary.bootstatScalarSummary.empty()) {
      html << "<div class=\"k\">bootstat scalars</div><div class=\"mono\">"
           << HtmlEscape(report.dynamicSummary.bootstatScalarSummary)
           << "</div>";
    }
    html << "<div class=\"k\">vCPU exits</div><div class=\"mono\">"
         << report.dynamicSummary.vcpuExits << "</div>";
    html << "<div class=\"k\">IDE commands</div><div class=\"mono\">"
         << report.dynamicSummary.ideCommandsIssued << "</div>";
    html << "<div class=\"k\">IDE reads</div><div class=\"mono\">"
         << report.dynamicSummary.ideReadCommands << " command(s), "
         << report.dynamicSummary.ideSectorsRead << " sector(s)</div>";
    if (report.dynamicSummary.ideSawRead) {
      html << "<div class=\"k\">IDE LBA read</div><div class=\"mono\">"
           << report.dynamicSummary.ideMinReadLba << "-"
           << report.dynamicSummary.ideMaxReadEndLba << "</div>";
    }
    if (report.dynamicSummary.ideSawWrite) {
      html << "<div class=\"k\">IDE LBA write</div><div class=\"mono\">"
           << report.dynamicSummary.ideMinWriteLba << "-"
           << report.dynamicSummary.ideMaxWriteEndLba << "</div>";
    }
    if (report.dynamicSummary.ideInterruptsRequested != 0 ||
        report.dynamicSummary.ideInterruptsPending != 0) {
      html << "<div class=\"k\">IDE IRQ</div><div class=\"mono\">"
           << report.dynamicSummary.ideInterruptsInjected << "/"
           << report.dynamicSummary.ideInterruptsRequested
           << " delivered, pending "
           << report.dynamicSummary.ideInterruptsPending << ", failed "
           << report.dynamicSummary.ideInterruptsFailed << "</div>";
    }
    if (report.dynamicSummary.irqIoApicDeliveries != 0 ||
        report.dynamicSummary.irqPicFallbackDeliveries != 0 ||
        report.dynamicSummary.irqDeliveryFailures != 0) {
      html << "<div class=\"k\">IRQ route</div><div class=\"mono\">ioapic "
           << report.dynamicSummary.irqIoApicDeliveries << ", pic "
           << report.dynamicSummary.irqPicFallbackDeliveries << ", failed "
           << report.dynamicSummary.irqDeliveryFailures << "</div>";
    }
    if (report.dynamicSummary.pm1SleepRequests != 0 ||
        report.dynamicSummary.pm1ControlValue != 0) {
      html << "<div class=\"k\">PM1 sleep</div><div class=\"mono\">"
           << "0x" << std::hex << std::uppercase
           << report.dynamicSummary.pm1ControlValue << std::dec
           << ", S" << report.dynamicSummary.pm1SleepType
           << ", stop "
           << (report.dynamicSummary.pm1HostStopRequested ? "yes" : "no")
           << "</div>";
    }
    if (report.dynamicSummary.fwCfgSmbiosAnchorBytesRead != 0 ||
        report.dynamicSummary.fwCfgSmbiosTableBytesRead != 0) {
      html << "<div class=\"k\">SMBIOS fw_cfg</div><div class=\"mono\">"
           << report.dynamicSummary.fwCfgSmbiosAnchorBytesRead
           << " anchor byte(s), "
           << report.dynamicSummary.fwCfgSmbiosTableBytesRead
           << " table byte(s)</div>";
    }
    if (report.dynamicSummary.kdPacketsReceived != 0 ||
        report.dynamicSummary.kdAckPacketsSent != 0 ||
        report.dynamicSummary.kdResendPacketsSent != 0 ||
        report.dynamicSummary.kdResetPacketsSent != 0) {
      html << "<div class=\"k\">KD COM1</div><div class=\"mono\">"
           << report.dynamicSummary.kdPacketsReceived << " packet(s), "
           << report.dynamicSummary.kdAckPacketsSent << " ACK, "
           << report.dynamicSummary.kdResetPacketsSent << " reset, "
           << report.dynamicSummary.kdCom1RxQueuedBytes << " queued RX byte(s), "
           << report.dynamicSummary.kdDebugPrintPackets << " print, "
           << report.dynamicSummary.kdLoadSymbolPackets << " symbols, "
           << report.dynamicSummary.kdAutoContinuesSent
           << " continue</div>";
      if (!report.dynamicSummary.kdLastStatusText.empty()) {
        html << "<div class=\"k\">KD status</div><div class=\"mono\">"
             << HtmlEscape(report.dynamicSummary.kdLastStatusText)
             << "</div>";
      }
    }
    if (!report.dynamicSummary.kdCom1Status.empty()) {
      html << "<div class=\"k\">KD COM1 state</div><div class=\"mono\">"
           << HtmlEscape(report.dynamicSummary.kdCom1Status) << "</div>";
    }
    if (!report.dynamicSummary.com1TouchStatus.empty() ||
        report.dynamicSummary.com1RegisterReads != 0 ||
        report.dynamicSummary.com1RegisterWrites != 0 ||
        report.dynamicSummary.com1RxBytesQueued != 0) {
      html << "<div class=\"k\">COM1 UART</div><div class=\"mono\">"
           << HtmlEscape(report.dynamicSummary.com1TouchStatus.empty()
                             ? "observed"
                             : report.dynamicSummary.com1TouchStatus)
           << ", regs r/w " << report.dynamicSummary.com1RegisterReads << "/"
           << report.dynamicSummary.com1RegisterWrites
           << ", data r/w " << report.dynamicSummary.com1DataReads << "/"
           << report.dynamicSummary.com1DataWrites
           << ", rx queued/read "
           << report.dynamicSummary.com1RxBytesQueued << "/"
           << report.dynamicSummary.com1RxBytesRead
           << ", IER 0x" << std::hex << std::uppercase
           << report.dynamicSummary.com1Ier << std::dec << "</div>";
    }
    if (report.dynamicSummary.tpmCrbReads != 0 ||
        report.dynamicSummary.tpmCrbWrites != 0 ||
        report.dynamicSummary.tpmCrbCommands != 0 ||
        !report.dynamicSummary.tpmCrbCommandSummary.empty()) {
      html << "<div class=\"k\">TPM2 CRB</div><div class=\"mono\">";
      if (!report.dynamicSummary.tpmCrbCommandSummary.empty()) {
        html << HtmlEscape(report.dynamicSummary.tpmCrbCommandSummary);
      } else {
        html << "reads/writes " << report.dynamicSummary.tpmCrbReads << "/"
             << report.dynamicSummary.tpmCrbWrites << ", commands "
             << report.dynamicSummary.tpmCrbCommands;
      }
      html << "</div>";
    }
    if (!report.dynamicSummary.tpmPcrExtendTraceSummary.empty()) {
      html << "<div class=\"k\">TPM PCR extend trace</div><div class=\"mono\">"
           << HtmlEscape(report.dynamicSummary.tpmPcrExtendTraceSummary)
           << "</div>";
    }
    if (!report.dynamicSummary.tpmPcrFinalBanksSummary.empty()) {
      html << "<div class=\"k\">TPM PCR final banks</div><div class=\"mono\">"
           << HtmlEscape(report.dynamicSummary.tpmPcrFinalBanksSummary)
           << "</div>";
    }
    if (!report.dynamicSummary.acpiTpm2EventLogSummary.empty()) {
      html << "<div class=\"k\">ACPI TPM2 event log</div><div class=\"mono\">"
           << HtmlEscape(report.dynamicSummary.acpiTpm2EventLogSummary)
           << "</div>";
    }
    if (report.dynamicSummary.keyboardScancodesInjected != 0 ||
        report.dynamicSummary.ps2StatusReads != 0 ||
        report.dynamicSummary.ps2DataReads != 0 ||
        !report.dynamicSummary.ps2InputStatus.empty()) {
      html << "<div class=\"k\">PS/2 input</div><div class=\"mono\">"
           << HtmlEscape(report.dynamicSummary.ps2InputStatus.empty()
                             ? "observed"
                             : report.dynamicSummary.ps2InputStatus)
           << ", injected "
           << report.dynamicSummary.keyboardScancodesInjected
           << ", queued/read "
           << report.dynamicSummary.ps2KeyboardBytesQueued << "/"
           << report.dynamicSummary.ps2KeyboardBytesRead
           << ", port reads "
           << report.dynamicSummary.ps2StatusReads << "/"
           << report.dynamicSummary.ps2DataReads << "</div>";
    }
    if (!report.dynamicSummary.cpuidDiagnostics.empty()) {
      html << "<div class=\"k\">CPUID</div><div class=\"mono\">";
      for (size_t i = 0; i < report.dynamicSummary.cpuidDiagnostics.size(); ++i) {
        if (i) {
          html << "<br>";
        }
        html << HtmlEscape(report.dynamicSummary.cpuidDiagnostics[i]);
      }
      html << "</div>";
    }
    if (!report.dynamicSummary.bootMilestones.empty()) {
      html << "<div class=\"k\">boot</div><div>";
      for (size_t i = 0; i < report.dynamicSummary.bootMilestones.size(); ++i) {
        if (i) {
          html << " &middot; ";
        }
        html << HtmlEscape(report.dynamicSummary.bootMilestones[i]);
      }
      html << "</div>";
    }
  }
  html << "<div class=\"k\">entropy</div><div class=\"mono\">"
       << scan.entropy << "</div>";
  html << "<div class=\"k\">PE</div><div>" << (scan.isPe ? "yes" : "no")
       << ", signed " << (scan.authenticodeSigned ? "yes" : "no");
  if (!scan.signerName.empty()) {
    html << " &middot; signer " << HtmlEscape(scan.signerName);
  }
  html << "</div>";
  html << "</div>";

  // Detections — the severity-ranked behavior summary an analyst reads first.
  {
    const auto dets = BuildDetections(report);
    if (!dets.empty()) {
      auto sevColor = [](int s) {
        return s >= 3 ? "var(--bad)"
                      : s == 2 ? "var(--warn)" : s == 1 ? "var(--accent)"
                                                        : "var(--muted)";
      };
      html << "<h2 style=\"margin-top:14px\">Detections (" << dets.size()
           << ")</h2><table><thead><tr><th>Severity</th><th>Category</th>"
              "<th>Detection</th><th>MITRE</th></tr></thead><tbody>";
      for (const auto &d : dets) {
        std::string mitreCell = HtmlEscape(d.mitre);
        if (!d.mitre.empty()) {
          const std::string nm = MitreTechniqueName(d.mitre);
          if (!nm.empty()) {
            const auto pos = nm.rfind(": ");
            mitreCell +=
                " <span style=\"opacity:.7\">" +
                HtmlEscape(pos == std::string::npos ? nm : nm.substr(pos + 2)) +
                "</span>";
          }
        }
        html << "<tr><td><span class=\"mono\" style=\"color:" << sevColor(d.severity)
             << "\">" << HtmlEscape(d.severityLabel) << "</span></td><td class=\"mono\">"
             << HtmlEscape(d.category) << "</td><td>" << HtmlEscape(d.title)
             << "</td><td class=\"mono\">" << mitreCell << "</td></tr>";
      }
      html << "</tbody></table>";
    }
  }

  // Tracker tags
  if (!scan.tags.empty()) {
    html << "<h2 style=\"margin-top:14px\">Tracker</h2><div>";
    EmitTags(html, scan.tags);
    html << "</div>";
  }

  // Process tree (if any events)
  auto forest = BuildProcessForest(report.events);
  if (!forest.nodes.empty()) {
    html << "<h2 style=\"margin-top:14px\">Processes (" << forest.nodes.size() << ")</h2>";
    html << EmitProcessTreeHtml(forest);
  }

  // Intel hits
  if (!scan.intelHits.empty()) {
    html << "<h2 style=\"margin-top:14px\">Threat intel</h2>";
    for (const auto &hit : scan.intelHits) {
      html << "<div class=\"kv\" style=\"margin-bottom:8px\">";
      html << "<div class=\"k\">" << HtmlEscape(hit.source) << "</div><div>";
      if (!hit.error.empty()) {
        html << "<span class=\"badge error\">error</span> "
             << HtmlEscape(hit.error);
      } else if (hit.known) {
        html << "<span class=\"badge malicious\">known</span> ";
        if (!hit.family.empty()) html << HtmlEscape(hit.family) << " ";
        if (hit.totalScanners > 0)
          html << "<span class=\"mono\">" << hit.detectionRatio << "/"
               << hit.totalScanners << "</span>";
      } else {
        html << "<span class=\"badge clean\">unknown</span>";
      }
      if (!hit.permalink.empty()) {
        html << " <a href=\"" << HtmlEscape(hit.permalink)
             << "\" target=\"_blank\" style=\"color:var(--accent)\">link</a>";
      }
      html << "</div></div>";
    }
  }

  html << "</section>";

  // PE static analysis: hashes + section table with per-section entropy. A
  // writable+executable or high-entropy section is the visible packer tell.
  if (scan.isPe && !scan.peSections.empty()) {
    html << "<section class=\"panel\"><h2>PE sections</h2>";
    if (scan.imphash.size() || scan.peTimestamp || scan.peOverlaySize ||
        scan.isDotNet || !scan.peExports.empty() || scan.tlsCallbackCount ||
        !scan.pdbPath.empty() || scan.peVersionInfo.present ||
        !scan.richHash.empty()) {
      html << "<div class=\"kv\">";
      if (!scan.imphash.empty()) {
        html << "<div class=\"k\">imphash</div><div class=\"mono\">"
             << HtmlEscape(scan.imphash) << "</div>";
      }
      if (scan.peTimestamp) {
        html << "<div class=\"k\">compiled (epoch)</div><div class=\"mono\">"
             << scan.peTimestamp << "</div>";
      }
      if (scan.peOverlaySize) {
        char ob[32];
        std::snprintf(ob, sizeof(ob), "%.2f", scan.peOverlayEntropy);
        html << "<div class=\"k\">overlay</div><div class=\"mono\">"
             << scan.peOverlaySize << " bytes, entropy " << ob << "</div>";
      }
      if (scan.isDotNet) {
        html << "<div class=\"k\">.NET</div><div>managed (CLR "
             << HtmlEscape(scan.dotNetRuntimeVersion) << ")</div>";
      }
      if (!scan.peExports.empty()) {
        html << "<div class=\"k\">exports</div><div>" << scan.peExports.size();
        if (!scan.exportName.empty()) {
          html << " &middot; " << HtmlEscape(scan.exportName);
        }
        html << "</div>";
      }
      if (scan.tlsCallbackCount) {
        html << "<div class=\"k\">TLS callbacks</div><div>"
             << scan.tlsCallbackCount << "</div>";
      }
      if (scan.peVersionInfo.present) {
        html << "<div class=\"k\">version</div><div>"
             << HtmlEscape(scan.peVersionInfo.companyName);
        if (!scan.peVersionInfo.productName.empty()) {
          html << " &middot; " << HtmlEscape(scan.peVersionInfo.productName);
        }
        if (!scan.peVersionInfo.originalFilename.empty()) {
          html << " (" << HtmlEscape(scan.peVersionInfo.originalFilename) << ")";
        }
        html << "</div>";
      }
      if (!scan.pdbPath.empty()) {
        html << "<div class=\"k\">PDB</div><div class=\"mono\">"
             << HtmlEscape(scan.pdbPath) << "</div>";
      }
      if (!scan.richHash.empty()) {
        html << "<div class=\"k\">richhash</div><div class=\"mono\">"
             << HtmlEscape(scan.richHash) << "</div>";
      }
      html << "</div>";
    }
    html << "<table><thead><tr><th>Name</th><th>Virtual</th><th>Raw</th>"
            "<th>Entropy</th><th>Flags</th></tr></thead><tbody>";
    for (const auto &sec : scan.peSections) {
      const bool hot = sec.executable && sec.entropy > 7.0;
      html << "<tr><td class=\"mono\">" << HtmlEscape(sec.name) << "</td><td>"
           << sec.virtualSize << "</td><td>" << sec.rawSize << "</td><td"
           << (hot ? " class=\"badge Malicious\"" : "") << ">";
      char buf[16];
      std::snprintf(buf, sizeof(buf), "%.2f", sec.entropy);
      html << buf << "</td><td class=\"mono\">" << (sec.executable ? "X" : "-")
           << (sec.writable ? "W" : "-") << "</td></tr>";
    }
    html << "</tbody></table></section>";
  }

  // Center column: screenshots + analyst-grade grouped sections + full timeline
  html << "<section class=\"panel\">";
  html << "<h2>Run timeline</h2>";
  EmitFilmstrip(html, displayFrames);

  // Analyst-grade grouped sections (Any.Run-style). Each renders ABOVE the full
  // event timeline and only when it has rows -- a helper buffers each into its
  // own ostringstream and we drop the section card when nothing was drawn.
  {
    std::ostringstream body;
    if (EmitProcessTreeSection(body, report.events)) {
      html << "<div class=\"section-card\"><h2>Process Tree</h2>" << body.str()
           << "</div>";
    }
  }
  {
    std::ostringstream body;
    if (EmitPersistenceSection(body, report.events)) {
      html << "<div class=\"section-card\"><h2>Persistence</h2>" << body.str()
           << "</div>";
    }
  }
  {
    std::ostringstream body;
    if (EmitDroppedFilesSection(body, report.events)) {
      html << "<div class=\"section-card\"><h2>Dropped Files</h2>" << body.str()
           << "</div>";
    }
  }
  {
    std::ostringstream body;
    if (EmitNetworkSection(body, report.events)) {
      html << "<div class=\"section-card\"><h2>Network</h2>" << body.str()
           << "</div>";
    }
  }
  {
    std::ostringstream body;
    if (EmitCrashesSection(body, report.events)) {
      html << "<div class=\"section-card\"><h2>Crashes</h2>" << body.str()
           << "</div>";
    }
  }
  {
    std::ostringstream body;
    if (EmitModuleLoadsSection(body, report.events)) {
      html << "<div class=\"section-card\"><h2>Module Loads</h2>" << body.str()
           << "</div>";
    }
  }
  {
    std::ostringstream body;
    if (EmitMitreChips(body, report.mitreTechniques)) {
      html << "<div class=\"section-card\"><h2>MITRE ATT&amp;CK</h2>"
           << body.str() << "</div>";
    }
  }

  html << "<h2 style=\"margin-top:16px\">Full Event Timeline</h2>";
  EmitEventTable(html, report.events);

  if (!scan.findings.empty()) {
    html << "<h2 style=\"margin-top:16px\">Scanner findings</h2>";
    html << "<table><thead><tr><th>Rule</th><th>Score</th><th>Message</th></tr></thead><tbody>";
    for (const auto &f : scan.findings) {
      html << "<tr><td class=\"mono\">" << HtmlEscape(f.ruleId) << "</td><td class=\"mono\">"
           << f.score << "</td><td>" << HtmlEscape(f.message) << "</td></tr>";
    }
    html << "</tbody></table>";
  }

  if (!scan.yaraMatches.empty()) {
    html << "<h2 style=\"margin-top:16px\">YARA</h2><table><thead><tr><th>Rule</th><th>Tags</th></tr></thead><tbody>";
    for (const auto &m : scan.yaraMatches) {
      html << "<tr><td class=\"mono\">" << HtmlEscape(m.ruleName) << "</td><td>";
      for (size_t i = 0; i < m.tags.size(); ++i) {
        if (i) html << ", ";
        html << HtmlEscape(m.tags[i]);
      }
      html << "</td></tr>";
    }
    html << "</tbody></table>";
  }

  if (!scan.capaCapabilities.empty()) {
    html << "<h2 style=\"margin-top:16px\">capa capabilities</h2><table><thead><tr><th>Rule</th><th>MITRE</th></tr></thead><tbody>";
    for (const auto &c : scan.capaCapabilities) {
      html << "<tr><td class=\"mono\">" << HtmlEscape(c.name) << "</td><td class=\"mono\">";
      for (size_t i = 0; i < c.mitreTechniques.size(); ++i) {
        if (i) html << " ";
        html << HtmlEscape(c.mitreTechniques[i]);
      }
      html << "</td></tr>";
    }
    html << "</tbody></table>";
  }

  if (!scan.dieDetections.empty()) {
    html << "<h2 style=\"margin-top:16px\">Detect It Easy</h2><table><thead><tr><th>Type</th><th>Name</th><th>Version</th></tr></thead><tbody>";
    for (const auto &d : scan.dieDetections) {
      html << "<tr><td>" << HtmlEscape(d.type) << "</td><td class=\"mono\">"
           << HtmlEscape(d.name) << "</td><td class=\"mono\">"
           << HtmlEscape(d.version) << "</td></tr>";
    }
    html << "</tbody></table>";
  }

  html << "</section>";

  // Right rail: IOCs + network + browser impact
  html << "<section class=\"panel\"><h2>Indicators</h2>";
  html << "<label style=\"font-size:12px;display:block;margin:-4px 0 8px;"
          "color:var(--muted)\"><input type=\"checkbox\" id=\"defang-toggle\"> "
          "defang IOCs (safe to share)</label>";
  html << "<div class=\"detail-grid\">";
  html << "<div><h2 style=\"margin-top:0\">URLs</h2>";
  EmitIocList(html, scan.iocs.urls, "no urls");
  html << "</div><div><h2 style=\"margin-top:0\">Domains</h2>";
  EmitIocList(html, scan.iocs.domains, "no domains");
  html << "</div></div>";
  html << "<div class=\"detail-grid\">";
  html << "<div><h2>IPs</h2>";
  EmitIocList(html, scan.iocs.ips, "no ips");
  html << "</div><div><h2>Mutexes</h2>";
  EmitIocList(html, scan.iocs.mutexHints, "no mutexes");
  html << "</div></div>";
  html << "<h2>Registry paths</h2>";
  EmitIocList(html, scan.iocs.registryPaths, "none");
  html << "<h2>File paths</h2>";
  EmitIocList(html, scan.iocs.filePaths, "none");
  if (!scan.iocs.suspiciousApis.empty()) {
    html << "<h2>Suspicious APIs in strings</h2>";
    EmitIocList(html, scan.iocs.suspiciousApis, "");
  }
  if (!report.networkDomains.empty()) {
    html << "<h2>Dynamic network</h2>";
    EmitIocList(html, report.networkDomains, "");
  }
  if (!report.artifacts.empty()) {
    html << "<h2>Artifacts</h2><ul>";
    for (const auto &artifact : report.artifacts) {
      html << "<li class=\"mono\">" << HtmlEscape(artifact.filename().string())
           << "</li>";
    }
    html << "</ul>";
  }
  if (!report.mitreTechniques.empty()) {
    html << "<h2>MITRE ATT&amp;CK</h2>";
    EmitMitreByTactic(html, report.mitreTechniques); // grouped by tactic (kill chain)
  }
  if (!report.browserImpact.empty()) {
    html << "<h2>Browser risk</h2><table><thead><tr><th>Domain</th><th>Creds</th><th>Cookies</th></tr></thead><tbody>";
    for (const auto &r : report.browserImpact) {
      html << "<tr><td class=\"mono\">" << HtmlEscape(r.domain)
           << "</td><td>" << (r.savedCredentials ? "yes" : "no")
           << "</td><td>" << (r.cookiesPresent ? "yes" : "no") << "</td></tr>";
    }
    html << "</tbody></table>";
  }
  if (!report.errors.empty()) {
    html << "<h2>Errors</h2><ul>";
    for (const auto &e : report.errors) html << "<li>" << HtmlEscape(e) << "</li>";
    html << "</ul>";
  }
  html << "</section>";

  html << "</main>";
  html << "<script>" << kJs << "</script>";
  html << "</body></html>";
  return html.str();
}

void WriteReportJson(const std::filesystem::path &path, const AnalysisReport &report) {
  WriteTextFile(path, ToJson(report));
}

void WriteReportHtml(const std::filesystem::path &path, const AnalysisReport &report) {
  const auto frames = DiscoverFramesNextTo(path);
  WriteTextFile(path, BuildHtmlReportWithFrames(report, frames));
}

std::vector<std::string> AggregateMitreTechniques(
    const std::vector<EventRecord> &events, const ScanResult &scan) {
  std::set<std::string> techniques; // std::set keeps them distinct + sorted
  for (const auto &e : events) {
    if (!e.mitre.empty()) {
      techniques.insert(e.mitre);
    }
  }
  // Union in the static capa-derived technique IDs (capa maps each capability to
  // zero or more ATT&CK technique strings). These corroborate / fill in for the
  // dynamic side without fabricating anything.
  for (const auto &cap : scan.capaCapabilities) {
    for (const auto &t : cap.mitreTechniques) {
      if (!t.empty()) {
        techniques.insert(t);
      }
    }
  }
  // Map the static scanner findings (file-type analyzers + obfuscation/config
  // recovery) to ATT&CK techniques, so a STATIC scan of a lure document/image
  // populates the report's ATT&CK matrix too (not just capa/dynamic). Only
  // high-confidence finding -> technique edges; nothing invented.
  static const std::map<std::string, std::vector<std::string>> kFindingTech = {
      {"rtf.equation_editor", {"T1203", "T1204.002", "T1566.001"}},
      {"rtf.objupdate", {"T1204.002", "T1566.001"}},
      {"rtf.remote_object_load", {"T1221", "T1566.001"}},
      {"rtf.ole_object", {"T1204.002"}},
      {"rtf.embedded_pe", {"T1204.002"}},
      {"iso.lnk_plus_exe", {"T1204.002", "T1553.005", "T1566.001"}},
      {"iso.embedded_exe", {"T1204.002", "T1553.005"}},
      {"iso.embedded_lnk", {"T1204.002"}},
      {"iso.small_payload_image", {"T1553.005"}},
      {"onenote.embedded_file", {"T1204.002", "T1566.001"}},
      {"onenote.embedded_exe", {"T1204.002"}},
      {"onenote.embedded_script", {"T1204.002", "T1059"}},
      {"strings.rc4_wrapped_config", {"T1027"}},
      {"strings.xor_obfuscated_url", {"T1027"}},
      {"strings.multibyte_xor_obfuscated_url", {"T1027"}},
      {"strings.base64_wrapped_ioc", {"T1027"}},
      {"config.cobalt_strike", {"T1071.001"}},
  };
  for (const auto &f : scan.findings) {
    const auto it = kFindingTech.find(f.ruleId);
    if (it != kFindingTech.end()) {
      for (const auto &t : it->second) techniques.insert(t);
    }
  }
  // Techniques implied by suspicious process-ancestry chains (maldoc execution,
  // proxy-exec, etc.) -- derived from the lineage, not present on the events.
  for (const auto &h : ClassifyProcessChains(events)) {
    if (!h.mitre.empty()) techniques.insert(h.mitre);
  }
  return std::vector<std::string>(techniques.begin(), techniques.end());
}

std::vector<std::string> AggregateNetworkDomains(
    const std::vector<EventRecord> &events) {
  // A by-name endpoint only: a string with at least one dot and no ':' (which
  // would mark it as an IP:port target) and no '/'. This deliberately rejects
  // the IP:port targets the in-guest TCP-table telemetry emits, so domains stay
  // empty until DNS/SNI capture lands rather than turning IPs into "domains".
  auto looksLikeHostname = [](const std::string &s) {
    if (s.empty() || s.size() > 253) return false;
    if (s.find(':') != std::string::npos || s.find('/') != std::string::npos) {
      return false;
    }
    if (s.find('.') == std::string::npos) return false;
    bool allDigitsOrDots = true;
    for (char c : s) {
      const unsigned char u = static_cast<unsigned char>(c);
      if (!(std::isalnum(u) || c == '.' || c == '-' || c == '_')) return false;
      if (!(c == '.' || std::isdigit(u))) allDigitsOrDots = false;
    }
    return !allDigitsOrDots; // reject a bare dotted-quad IP (e.g. "1.2.3.4")
  };
  std::set<std::string> domains; // distinct + sorted
  for (const auto &e : events) {
    if (e.category != "network") continue;
    // DNS query name: PacketInspector puts the queried hostname in target.
    if (e.action == "network.dns" && looksLikeHostname(e.target)) {
      domains.insert(e.target);
    }
    // HTTP Host header: PacketInspector records it in details["host"].
    const auto it = e.details.find("host");
    if (it != e.details.end() && looksLikeHostname(it->second)) {
      domains.insert(it->second);
    }
  }
  return std::vector<std::string>(domains.begin(), domains.end());
}

std::vector<std::string> ExtractNetworkDomainsFromReportText(std::string_view jsonText) {
  std::vector<std::string> domains;
  const std::string text(jsonText);
  std::regex quotedDomain("\"([A-Za-z0-9._-]+\\.[A-Za-z]{2,})\"");
  for (auto it = std::sregex_iterator(text.begin(), text.end(), quotedDomain);
       it != std::sregex_iterator(); ++it) {
    domains.push_back((*it)[1].str());
  }
  std::sort(domains.begin(), domains.end());
  domains.erase(std::unique(domains.begin(), domains.end()), domains.end());
  return domains;
}

AnalysisReport LoadReportBestEffort(const std::filesystem::path &path) {
  const std::string text = ReadTextFile(path);
  try {
    return ParseReportJson(text, path);
  } catch (...) {
  }

  AnalysisReport report;
  report.runId = path.stem().string();
  report.networkDomains = ExtractNetworkDomainsFromReportText(text);

  std::regex runId("\"runId\"\\s*:\\s*\"([^\"]+)\"");
  std::smatch match;
  if (std::regex_search(text, match, runId)) {
    report.runId = match[1].str();
  }
  std::regex sample("\"samplePath\"\\s*:\\s*\"([^\"]+)\"");
  if (std::regex_search(text, match, sample)) {
    report.samplePath = Utf8ToWide(match[1].str());
  }
  return report;
}

} // namespace antimal
