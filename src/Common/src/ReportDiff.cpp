#include "antimal/ReportDiff.h"

#include <algorithm>
#include <iterator>
#include <set>
#include <sstream>

namespace antimal {
namespace {

void AddAll(std::set<std::string> &s, const std::string &kind,
            const std::vector<std::string> &vals) {
  for (const auto &v : vals) {
    if (!v.empty()) s.insert(kind + ":" + v);
  }
}

std::set<std::string> IocSet(const AnalysisReport &r) {
  std::set<std::string> s;
  const auto &i = r.scannerVerdict.iocs;
  AddAll(s, "url", i.urls);
  AddAll(s, "ip", i.ips);
  AddAll(s, "domain", i.domains);
  AddAll(s, "reg", i.registryPaths);
  AddAll(s, "file", i.filePaths);
  AddAll(s, "mutex", i.mutexHints);
  AddAll(s, "api", i.suspiciousApis);
  AddAll(s, "domain", r.networkDomains); // dynamic-resolved domains too
  return s;
}

std::set<std::string> FindingSet(const AnalysisReport &r) {
  std::set<std::string> s;
  for (const auto &f : r.scannerVerdict.findings) {
    if (!f.ruleId.empty()) s.insert(f.ruleId);
  }
  return s;
}

std::set<std::string> MitreSet(const AnalysisReport &r) {
  return std::set<std::string>(r.mitreTechniques.begin(),
                               r.mitreTechniques.end());
}

std::set<std::string> TagSet(const AnalysisReport &r) {
  std::set<std::string> s;
  for (const auto &t : r.scannerVerdict.tags) {
    if (!t.tag.empty()) s.insert(t.tag);
  }
  return s;
}

// Sorted items present in `b` but not in `a`.
std::vector<std::string> OnlyIn(const std::set<std::string> &a,
                                const std::set<std::string> &b) {
  std::vector<std::string> out;
  std::set_difference(b.begin(), b.end(), a.begin(), a.end(),
                      std::back_inserter(out));
  return out;
}

} // namespace

bool ReportDiff::Identical() const {
  return !sandboxVerdictChanged && !scannerVerdictChanged &&
         oldScannerScore == newScannerScore && addedIocs.empty() &&
         removedIocs.empty() && addedFindings.empty() &&
         removedFindings.empty() && addedMitre.empty() && removedMitre.empty() &&
         addedTags.empty() && removedTags.empty();
}

ReportDiff DiffReports(const AnalysisReport &a, const AnalysisReport &b) {
  ReportDiff d;
  d.oldSandboxVerdict = a.sandboxVerdict;
  d.newSandboxVerdict = b.sandboxVerdict;
  d.sandboxVerdictChanged = a.sandboxVerdict != b.sandboxVerdict;
  d.oldScannerVerdict = a.scannerVerdict.verdict;
  d.newScannerVerdict = b.scannerVerdict.verdict;
  d.scannerVerdictChanged = a.scannerVerdict.verdict != b.scannerVerdict.verdict;
  d.oldScannerScore = a.scannerVerdict.score;
  d.newScannerScore = b.scannerVerdict.score;

  const auto ia = IocSet(a), ib = IocSet(b);
  d.addedIocs = OnlyIn(ia, ib);
  d.removedIocs = OnlyIn(ib, ia);
  const auto fa = FindingSet(a), fb = FindingSet(b);
  d.addedFindings = OnlyIn(fa, fb);
  d.removedFindings = OnlyIn(fb, fa);
  const auto ma = MitreSet(a), mb = MitreSet(b);
  d.addedMitre = OnlyIn(ma, mb);
  d.removedMitre = OnlyIn(mb, ma);
  const auto ta = TagSet(a), tb = TagSet(b);
  d.addedTags = OnlyIn(ta, tb);
  d.removedTags = OnlyIn(tb, ta);

  d.oldEventCount = static_cast<int>(a.events.size());
  d.newEventCount = static_cast<int>(b.events.size());
  return d;
}

std::string FormatReportDiff(const ReportDiff &d) {
  std::ostringstream o;
  o << "sandbox verdict: " << ToString(d.oldSandboxVerdict) << " -> "
    << ToString(d.newSandboxVerdict)
    << (d.sandboxVerdictChanged ? "  (changed)" : "  (same)") << "\n";
  o << "scanner verdict: " << ToString(d.oldScannerVerdict) << " ("
    << d.oldScannerScore << ") -> " << ToString(d.newScannerVerdict) << " ("
    << d.newScannerScore << ")"
    << ((d.scannerVerdictChanged || d.oldScannerScore != d.newScannerScore)
            ? "  (changed)"
            : "  (same)")
    << "\n";
  o << "events: " << d.oldEventCount << " -> " << d.newEventCount << "\n";

  auto emit = [&](const char *label, const std::vector<std::string> &add,
                  const std::vector<std::string> &rem) {
    o << label << ": +" << add.size() << " -" << rem.size() << "\n";
    for (const auto &x : add) o << "  + " << x << "\n";
    for (const auto &x : rem) o << "  - " << x << "\n";
  };
  emit("IOCs", d.addedIocs, d.removedIocs);
  emit("findings", d.addedFindings, d.removedFindings);
  emit("MITRE", d.addedMitre, d.removedMitre);
  emit("tags", d.addedTags, d.removedTags);
  if (d.Identical()) {
    o << "(reports are materially identical)\n";
  }
  return o.str();
}

} // namespace antimal
