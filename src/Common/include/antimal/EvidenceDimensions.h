#pragma once
#include "antimal/Types.h"
#include "antimal/EventTime.h"
#include <algorithm>
#include <set>

namespace antimal {
struct EventAttribution {
  std::string relationship = "unknown";
  std::string instance;
  std::string basis = "No unambiguous process instance at the event time";
};
struct EvidenceDimensions {
  std::string assessment;
  std::string assessmentBasis;
  std::map<std::string, size_t> observedCategories;
  std::vector<EventAttribution> attribution;
};
// Presentation classification, not an additional malware detector. Static
// scores and signature results are deliberately not read by this function.
inline EvidenceDimensions BuildEvidenceDimensions(const AnalysisReport& report) {
  EvidenceDimensions out;
  bool executed = report.dynamicSummary.sampleExecuted;
  for (const auto& e : report.events) {
    auto v = e.details.find("sampleExecuted");
    if (e.action == "process.create" && v != e.details.end() && v->second == "true") executed = true;
  }
  if (!executed || report.events.empty()) {
    out.assessment = "Insufficient observation";
  } else if (report.sandboxVerdict == Verdict::Malicious || report.sandboxVerdict == Verdict::Suspicious) {
    out.assessment = "Suspicious behavior requiring investigation";
  } else if (report.dynamicSummary.coverageIncomplete || report.verdictInsufficientEvidence || !report.dynamicSummary.completed) {
    out.assessment = "Insufficient observation; no harmful behavior established";
  } else {
    out.assessment = "No harmful behavior established under tested coverage";
  }
  out.assessmentBasis = "Behavioral indicators require their recorded attribution and coverage. "
      "Neither a heuristic score nor provenance confirms malicious intent. "
      "No observed harm is not a safety certification; module-level causality is not inferred from a hosting PID.";

  struct Instance { uint32_t pid = 0; int64_t start = -1, end = -1; std::string parent; };
  std::map<std::string, Instance> instances;
  auto detail = [](const EventRecord& e, const char* key) {
    auto p = e.details.find(key); return p == e.details.end() ? std::string{} : p->second;
  };
  for (const auto& e : report.events) {
    if (detail(e,"provider") != "Microsoft-Windows-Kernel-Process") continue;
    const auto seq = detail(e,"data.ProcessSequenceNumber");
    if (seq.empty()) continue;
    auto& i = instances[seq];
    if (detail(e,"eventId") == "1") {
      i.pid = e.processId; i.start = ParseIso8601ToEpochSeconds(detail(e,"startTime"));
      i.parent = detail(e,"data.ParentProcessSequenceNumber");
    } else if (detail(e,"eventId") == "2") {
      i.end = ParseIso8601ToEpochSeconds(detail(e,"data.ExitTime"));
    }
  }
  std::set<std::string> roots, owned;
  int64_t firstLaunch = -1;
  for (const auto& e : report.events) {
    if (e.action != "process.create" || detail(e,"sampleExecuted") != "true") continue;
    const auto t = ParseIso8601ToEpochSeconds(detail(e,"startTime"));
    if (t < 0) continue;
    if (firstLaunch < 0 || t < firstLaunch) firstLaunch = t;
    std::vector<std::string> matches;
    for (const auto& [seq,i] : instances) if (i.pid == e.processId && i.start == t) matches.push_back(seq);
    if (matches.size() == 1) roots.insert(matches.front());
  }
  owned = roots;
  for (size_t pass = 0; pass < instances.size(); ++pass) {
    const auto before = owned.size();
    for (const auto& [seq,i] : instances) if (!i.parent.empty() && owned.count(i.parent)) owned.insert(seq);
    if (before == owned.size()) break;
  }
  std::map<uint32_t, std::vector<std::string>> byPid;
  for (const auto& [seq,i] : instances) if (i.start >= 0) byPid[i.pid].push_back(seq);
  for (const auto& e : report.events) {
    ++out.observedCategories[e.category];
    EventAttribution a;
    const auto eventTime = ParseIso8601ToEpochSeconds(e.timestampUtc);
    uint32_t pid = e.processId;
    if (detail(e,"provider") == "Microsoft-Windows-DNS-Client") {
      const auto client = detail(e,"data.ClientPID");
      if (!client.empty() && client.size() <= 10 && std::all_of(client.begin(),client.end(),[](char c){return c >= '0' && c <= '9';})) {
        try { const auto n = std::stoull(client); if (n <= UINT32_MAX) pid = static_cast<uint32_t>(n); } catch (...) {}
      }
    }
    const auto id = detail(e,"eventId");
    const bool nameMetadata = detail(e,"provider") == "Microsoft-Windows-Kernel-File" && (id == "10" || id == "11");
    if (e.action == "process.crash" && e.source == "GuestAgent") {
      a.basis = "Crash snapshot PID can identify the collector, not the crashed process; instance attribution not established";
    } else if (nameMetadata) {
      a.basis = "File-name lifecycle metadata; header PID is not proof of an accessor";
    } else if (pid == 0 && (e.category == "file" || e.category == "registry") && firstLaunch >= 0 && eventTime >= firstLaunch) {
      a.relationship = "time-correlated-only";
      a.basis = "Post-launch delta without writer identity";
    } else if (eventTime >= 0) {
      std::vector<std::string> matches;
      for (const auto& seq : byPid[pid]) {
        const auto& i = instances.at(seq);
        // Seconds-only boundaries can overlap. Multiple candidates remain unknown.
        if (eventTime >= i.start && (i.end < 0 || eventTime <= i.end)) matches.push_back(seq);
      }
      if (matches.size() == 1) {
        a.instance = matches.front();
        a.relationship = roots.count(a.instance) ? "sample-instance" : owned.count(a.instance) ? "child-process" : "unrelated-background";
        a.basis = "ETW process sequence and recorded lifetime; ancestry is not module-level causality. "
            "Outside-tree/background classification does not exclude service-mediated activity";
      }
    }
    if (detail(e,"provider") == "Microsoft-Windows-Kernel-File" && id == "15" && detail(e,"data.FileName").empty()) {
      a.basis += "; read path is inferred from collector FileObject mapping, without recorded close-lifetime validation; path association requires corroboration";
    }
    out.attribution.push_back(std::move(a));
  }
  return out;
}
}
