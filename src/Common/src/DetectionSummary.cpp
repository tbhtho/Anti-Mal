#include "antimal/DetectionSummary.h"

#include "antimal/NetworkClassifier.h"
#include "antimal/PersistenceClassifier.h"

#include <algorithm>
#include <set>

namespace antimal {
namespace {

const char *Label(int sev) {
  switch (sev) {
    case 3: return "high";
    case 2: return "medium";
    case 1: return "low";
    default: return "info";
  }
}

int SeverityForScore(int score) {
  if (score >= 60) return 3;
  if (score >= 30) return 2;
  if (score >= 10) return 1;
  return 0;
}

bool ActionContains(const EventRecord &e, const char *s) {
  return e.action.find(s) != std::string::npos;
}

} // namespace

std::vector<Detection> BuildDetections(const AnalysisReport &report) {
  std::vector<Detection> out;
  std::set<std::string> seen; // category|title dedup

  auto add = [&](int sev, const std::string &cat, const std::string &title,
                 const std::string &mitre) {
    if (title.empty()) return;
    const std::string key = cat + "|" + title;
    if (!seen.insert(key).second) return;
    out.push_back({sev, Label(sev), cat, title, mitre});
  };

  // 1) Static scan findings (skip score-0 intel-only rows).
  for (const auto &f : report.scannerVerdict.findings) {
    if (f.score <= 0) continue;
    add(SeverityForScore(f.score), "static", f.message, "");
  }

  // 2) Persistence writes (classified from raw registry/file targets).
  for (const auto &e : report.events) {
    const bool isReg =
        e.category == "registry" || e.action.find("registry") != std::string::npos;
    const bool isFile = e.category == "file" &&
                        (ActionContains(e, "file.create") ||
                         ActionContains(e, "file.modify"));
    if (!isReg && !isFile) continue;
    const PersistenceMatch m = ClassifyPersistence(e.category, e.target);
    if (!m.matched) continue;
    add(2, "persistence", m.mechanism + ": " + e.target,
        e.mitre.empty() ? m.mitre : e.mitre);
  }

  // 3) Suspicious network endpoints.
  for (const auto &e : report.events) {
    if (e.category != "network") continue;
    const NetworkIndicator ni = ClassifyEndpoint(e.target);
    if (!ni.suspicious) continue;
    add(3, "network", ni.note + ": " + e.target, e.mitre);
  }

  std::sort(out.begin(), out.end(), [](const Detection &a, const Detection &b) {
    if (a.severity != b.severity) return a.severity > b.severity;
    if (a.category != b.category) return a.category < b.category;
    return a.title < b.title;
  });
  return out;
}

} // namespace antimal
