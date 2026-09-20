#include "antimal/BehaviorScore.h"

#include <algorithm>
#include <cctype>
#include <cstdlib> // std::atoi
#include <cstring>
#include <map>
#include <set>
#include <string>

namespace antimal {
namespace {

std::string Lower(std::string v) {
  for (char &c : v) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return v;
}

bool Has(const std::string &haystack, const char *needle) {
  return haystack.find(needle) != std::string::npos;
}

bool EndsWith(const std::string &h, const char *suf) {
  const size_t n = std::strlen(suf);
  return h.size() >= n && h.compare(h.size() - n, n, suf) == 0;
}

const std::string *Detail(const EventRecord &e, const char *key) {
  const auto it = e.details.find(key);
  return it == e.details.end() ? nullptr : &it->second;
}

bool DetailIsTrue(const EventRecord &e, const char *key) {
  const std::string *v = Detail(e, key);
  if (v == nullptr) {
    return false;
  }
  const std::string l = Lower(*v);
  return l == "true" || l == "1" || l == "yes";
}

// An integrity level worth elevating *to*. We compare a child's level against
// its parent: a jump from Medium/Low up to High/System is a privilege-escalation
// indicator. Returns a rank; higher = more privileged. Unknown levels rank 0.
int IntegrityRank(const std::string &level) {
  const std::string l = Lower(level);
  if (l == "system" || Has(l, "system")) {
    return 4;
  }
  if (Has(l, "high")) {
    return 3;
  }
  if (Has(l, "medium")) {
    return 2;
  }
  if (Has(l, "low")) {
    return 1;
  }
  if (Has(l, "untrusted")) {
    return 0;
  }
  return 0; // unknown / appcontainer / not captured
}

// --- Action semantics -------------------------------------------------------
// The collector's poll-diff telemetry distinguishes baseline inventory,
// mutations, and deletions. The scorer must never collapse them.

bool ActionHasAny(const std::string &lowerAct,
                  std::initializer_list<const char *> needles) {
  for (const char *n : needles) {
    if (Has(lowerAct, n)) {
      return true;
    }
  }
  return false;
}

bool IsRegistryDeleteAction(const std::string &act) {
  return ActionHasAny(act, {"delete", "remove", "delkey", "deleted"});
}

bool IsRegistryMutationAction(const std::string &act) {
  return ActionHasAny(act, {"create", "set", "write", "modify", "add", "new"});
}

// Baseline/inventory/read action. Checked AFTER delete/mutation so
// "registry.setvalue" is a mutation even though it contains "value".
bool IsRegistryReadAction(const std::string &act) {
  return ActionHasAny(act,
                      {"value", "read", "query", "enum", "baseline", "snapshot",
                       "open", "observed"});
}

bool IsFileMutationAction(const std::string &act) {
  return ActionHasAny(act, {"create", "write", "drop", "modify", "rename"});
}

bool IsProcessStartAction(const std::string &act) {
  return ActionHasAny(act, {"create", "start", "spawn", "running"}) &&
         !Has(act, "failed") && !Has(act, "stop") && !Has(act, "exit");
}

// A persistence-relevant registry location (autostart / service / helper).
bool IsAutostartTarget(const std::string &tgtL) {
  return Has(tgtL, "currentversion\\run") || Has(tgtL, "\\runonce") ||
         Has(tgtL, "winlogon") || Has(tgtL, "\\services\\") ||
         EndsWith(tgtL, "\\services") || Has(tgtL, "\\run\\") ||
         EndsWith(tgtL, "\\run") || Has(tgtL, "\\startup\\") ||
         EndsWith(tgtL, "\\startup") || Has(tgtL, "startupapproved") ||
         Has(tgtL, "ifeo") || Has(tgtL, "appinit") || Has(tgtL, "activesetup") ||
         Has(tgtL, "shellfolders");
}

bool LooksExecutable(const std::string &tgtL, const std::string &fileTypeLower) {
  const bool execByType =
      fileTypeLower == "pe" || fileTypeLower == "elf" ||
      fileTypeLower == "macho" || fileTypeLower == "script" ||
      fileTypeLower == "php" || fileTypeLower == "lnk";
  if (execByType) {
    return true;
  }
  return EndsWith(tgtL, ".exe") || EndsWith(tgtL, ".dll") ||
         EndsWith(tgtL, ".scr") || EndsWith(tgtL, ".sys") ||
         EndsWith(tgtL, ".ps1") || EndsWith(tgtL, ".bat") ||
         EndsWith(tgtL, ".cmd") || EndsWith(tgtL, ".vbs") ||
         EndsWith(tgtL, ".js") || EndsWith(tgtL, ".jse") ||
         EndsWith(tgtL, ".hta") || EndsWith(tgtL, ".jar") ||
         EndsWith(tgtL, ".msi") || EndsWith(tgtL, ".com") ||
         EndsWith(tgtL, ".cpl");
}

// A user-writable / transient location where a dropped executable is a staging
// tell rather than an installation.
bool IsStagingLocation(const std::string &tgtL) {
  if (tgtL.empty()) {
    return false;
  }
  if (Has(tgtL, "\\program files")) {
    return false;
  }
  if (Has(tgtL, "\\temp\\") || Has(tgtL, "\\tmp\\") ||
      Has(tgtL, "\\appdata\\") || Has(tgtL, "\\downloads\\") ||
      Has(tgtL, "\\public\\") || Has(tgtL, "\\startup\\") ||
      Has(tgtL, "\\desktop\\") || Has(tgtL, "\\documents\\") ||
      Has(tgtL, "\\programdata\\") || Has(tgtL, "\\windows\\temp\\")) {
    return true;
  }
  // Root of a drive: "c:\evil.exe" (drive letter, colon, one separator, then a
  // file name with no further directory component).
  if (tgtL.size() > 3 && tgtL[1] == ':' && tgtL[2] == '\\' &&
      tgtL.find('\\', 3) == std::string::npos) {
    return true;
  }
  return false;
}

// Is `target` an outbound endpoint that is NOT loopback and NOT an RFC1918 /
// link-local / CGN private range? Best-effort over an "ip" or "ip:port" /
// "host:port" string. A bare hostname (no dotted-quad) is treated as external
// because it implies name resolution to somewhere off-box.
bool IsExternalEndpoint(const std::string &targetRaw) {
  if (targetRaw.empty()) {
    return false;
  }
  const std::string t = Lower(targetRaw);
  if (Has(t, "127.0.0.1") || Has(t, "::1") || Has(t, "localhost")) {
    return false;
  }
  // Strip a trailing :port so prefix checks below see the bare address.
  std::string addr = t;
  if (const auto colon = addr.find_last_of(':'); colon != std::string::npos) {
    // Only strip if what follows is all digits (a port), so we don't mangle
    // an IPv6 literal. Conservative: leave IPv6 intact.
    const std::string tail = addr.substr(colon + 1);
    const bool allDigits =
        !tail.empty() && std::all_of(tail.begin(), tail.end(), [](char c) {
          return std::isdigit(static_cast<unsigned char>(c)) != 0;
        });
    if (allDigits && addr.find("::") == std::string::npos) {
      addr = addr.substr(0, colon);
    }
  }
  // RFC1918 / loopback / link-local / CGN private prefixes -> internal egress.
  static const char *kPrivatePrefixes[] = {
      "10.",      "192.168.", "169.254.", "0.0.0.0", "::",
      "fe80:",    "fc00:",    "fd",       /* unique-local IPv6 */
  };
  for (const char *p : kPrivatePrefixes) {
    if (addr.rfind(p, 0) == 0) {
      return false;
    }
  }
  if (addr.rfind("172.", 0) == 0) {
    // 172.16.0.0 - 172.31.255.255 is private; 172.0-15 / 172.32-255 are public.
    const size_t dot2 = addr.find('.', 4);
    if (dot2 != std::string::npos) {
      const int second = std::atoi(addr.substr(4, dot2 - 4).c_str());
      if (second >= 16 && second <= 31) {
        return false;
      }
    }
  }
  if (addr.rfind("100.", 0) == 0) {
    // 100.64.0.0/10 is carrier-grade NAT -- not real external egress.
    const size_t dot2 = addr.find('.', 4);
    if (dot2 != std::string::npos) {
      const int second = std::atoi(addr.substr(4, dot2 - 4).c_str());
      if (second >= 64 && second <= 127) {
        return false;
      }
    }
  }
  return true;
}

// Living-off-the-land / loader command-line tells. Each match adds modest
// weight; returns a short label naming the technique for the rationale.
const char *SuspiciousCommandLineLabel(const std::string &cmdRaw) {
  const std::string c = Lower(cmdRaw);
  if (c.empty()) {
    return nullptr;
  }
  if ((Has(c, "powershell") || Has(c, "pwsh")) &&
      (Has(c, "-enc") || Has(c, "-encodedcommand") || Has(c, "/enc") ||
       Has(c, "frombase64string"))) {
    return "powershell encoded command";
  }
  if ((Has(c, "powershell") || Has(c, "pwsh")) &&
      (Has(c, "-w hidden") || Has(c, "-windowstyle hidden") ||
       Has(c, "-nop") || Has(c, "-noprofile")) &&
      (Has(c, "iex") || Has(c, "downloadstring") || Has(c, "invoke-expression") ||
       Has(c, "-enc"))) {
    return "hidden powershell download/exec";
  }
  // rundll32 abuse. NOTE: do NOT match a bare "shell32" -- `rundll32
  // shell32.dll,Control_RunDLL` (Control Panel applets), ShellExec_RunDLL and
  // OpenAs_RunDLL are run constantly + legitimately by Windows shell/boot, so the
  // old `Has(c,"shell32")` clause was a steady false positive. The genuine
  // anomalies are a script protocol, url.dll,OpenURL, or a DLL masquerading under
  // an image/data extension (a common payload-hiding trick).
  if (Has(c, "rundll32") &&
      (Has(c, "javascript:") || Has(c, "url.dll") || Has(c, ".jpg") ||
       Has(c, ".png") || Has(c, ".dat") || Has(c, ".tmp"))) {
    return "rundll32 with anomalous arguments";
  }
  if (Has(c, "mshta") &&
      (Has(c, "http://") || Has(c, "https://") || Has(c, "javascript:") ||
       Has(c, "vbscript:"))) {
    return "mshta remote/script payload";
  }
  if (Has(c, "regsvr32") &&
      (Has(c, "/i:http") || Has(c, "-i:http") || Has(c, "scrobj") ||
       Has(c, "/s /n /u"))) {
    return "regsvr32 scriptlet / remote register";
  }
  if (Has(c, "certutil") &&
      (Has(c, "-urlcache") || Has(c, "-decode") || Has(c, "-decodehex"))) {
    return "certutil download/decode";
  }
  if (Has(c, "bitsadmin") &&
      (Has(c, "/transfer") || Has(c, "/addfile") || Has(c, "/create"))) {
    return "bitsadmin transfer";
  }
  if ((Has(c, "wscript") || Has(c, "cscript")) &&
      (Has(c, "\\temp\\") || Has(c, "\\appdata\\") || Has(c, "%temp%") ||
       Has(c, "/temp/") || EndsWith(c, ".js") || EndsWith(c, ".vbs"))) {
    return "wscript/cscript on temp path";
  }
  return nullptr;
}

// Consent state for an observed elevation. The collector/policy layer records
// details["elevationApproved"] when it knows the answer; ABSENCE of that field
// is Unknown, not "unapproved". Treating missing consent information as proof
// of unauthorized escalation would turn every unrecorded UAC prompt into
// evidence of malice -- exactly the false certainty the 2026-09 review flagged.
enum class ElevationConsent { Unknown, Approved, NotApproved };

ElevationConsent ElevationConsentOf(const EventRecord &e) {
  const std::string *v = Detail(e, "elevationApproved");
  if (v == nullptr) {
    return ElevationConsent::Unknown;
  }
  const std::string l = Lower(*v);
  if (l == "true" || l == "1" || l == "yes" || l == "approved") {
    return ElevationConsent::Approved;
  }
  if (l == "false" || l == "0" || l == "no" || l == "denied" ||
      l == "notapproved" || l == "not-approved") {
    return ElevationConsent::NotApproved;
  }
  return ElevationConsent::Unknown;
}

// How an observed event relates to the sample.
//   ProcessAttributed : owning process instance is in the sample's subtree.
//   OtherProcess      : owning PID belongs to a different (identified) process.
//   TimeCorrelated    : no PID was captured, but the event falls inside the
//                       sample's post-launch window (defensible temporal
//                       correlation; NOT process attribution).
//   Unowned           : no PID and no usable time relation.
//   NoRoot            : the run recorded no sample-launch anchor, so NOTHING is
//                       attributable (fails closed).
enum class Ownership {
  ProcessAttributed,
  OtherProcess,
  TimeCorrelated,
  Unowned,
  NoRoot,
};

bool EqualInsensitive(const std::string &a, const std::string &b) {
  if (a.size() != b.size()) {
    return false;
  }
  for (size_t i = 0; i < a.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(a[i])) !=
        std::tolower(static_cast<unsigned char>(b[i]))) {
      return false;
    }
  }
  return true;
}

// A base file name that Windows resolves through the search order and that
// malware commonly shadows (DLL planting next to an application). A module with
// one of these names loaded from a writable, non-system path is the classic
// search-order-hijack shape; an arbitrary support DLL in %TEMP% is not.
bool IsKnownShadowedDllName(const std::string &pathLower) {
  const size_t slash = pathLower.find_last_of("\\/");
  const std::string base =
      slash == std::string::npos ? pathLower : pathLower.substr(slash + 1);
  static const char *kShadowable[] = {
      "version.dll",  "winmm.dll",    "dwmapi.dll",  "uxtheme.dll",
      "propsys.dll",  "dbghelp.dll",  "cryptbase.dll", "secur32.dll",
      "wtsapi32.dll", "profapi.dll",  "amsi.dll",    "mpr.dll",
      "msimg32.dll",  "dbgcore.dll",  "d3d9.dll",    "d3d11.dll",
      "dxgi.dll",     "textinputframework.dll"};
  for (const char *n : kShadowable) {
    if (base == n) {
      return true;
    }
  }
  return false;
}

const char *OwnershipLabel(Ownership o) {  switch (o) {
  case Ownership::ProcessAttributed:
    return "process-attributed";
  case Ownership::OtherProcess:
    return "other-process";
  case Ownership::TimeCorrelated:
    return "time-correlated";
  case Ownership::Unowned:
    return "unowned";
  case Ownership::NoRoot:
    return "no-anchor";
  }
  return "unknown";
}

} // namespace

bool JournalShowsSampleExecuted(const std::vector<EventRecord> &events) {
  for (const auto &e : events) {
    if (Lower(e.category) != "process" || e.processId == 0) {
      continue;
    }
    const std::string a = Lower(e.action);
    if (Has(a, "create") && !Has(a, "failed") &&
        DetailIsTrue(e, "sampleExecuted")) {
      return true;
    }
  }
  return false;
}

// Signal weights (behavior-score-v4). Strong sample-attributable signals can
// reach the Malicious threshold; time-correlated (poll-diff) observations
// contribute at reduced weight and can never unlock the attributed-malice gate;
// other-process / unanchored activity contributes nothing.
//
//   attributed persistence (per target, MITRE-confirmed or autostart)  +35
//   time-correlated persistence (no PID, inside the sample window)     +20
//   attributed executable/script drop to a staging path (per target)   +15
//   attributed executable/DLL write to an install path (context)       +5
//   time-correlated executable drop                                    +8
//   attributed external network egress (first; +8 each extra, capped)  +20
//   attributed suspicious command line (per distinct technique)        +15
//   attributed DLL side-load / search-order hijack (first; then +8)    +25
//   unapproved elevation (explicit consent denial only)                +20
//   attributed data drop (non-exec, capped)                            +3
//   sample crash / non-sample crash (capped)                        +8 / +6
//   other attributed MITRE-tagged behavior (per event, capped)         +6
BehaviorScore ScoreSandboxBehavior(const DynamicRunSummary &summary,
                                   const std::vector<EventRecord> &events,
                                   bool sampleSigned) {
  BehaviorScore out;
  (void)sampleSigned; // Kept for call-site compatibility; provenance never changes behavior scoring.
  out.scorerVersion = kBehaviorScorerVersion;

  // Execution ground truth: the summary flag is set from the guest's completion
  // frame, which NEVER arrives for an "until stopped" run the operator finalized
  // while the sample was still alive. The journal's VERIFIED anchor
  // (details.sampleExecuted) is ground truth that the sample executed, so the
  // scorer must not report "not executed" for a fixture that clearly ran.
  const bool executed =
      summary.sampleExecuted || JournalShowsSampleExecuted(events);

  // Nothing ran (gated/healthcheck) or no telemetry at all -> inconclusive.
  if (!executed || events.empty()) {
    out.verdict = Verdict::Unknown;
    out.insufficientEvidence = true;
    if (!executed) {
      out.rationale.push_back(
          "Sample was not executed (gated or healthcheck-only run); no "
          "behavior to judge.");
      out.limitations.push_back(
          "the sample was not executed in this run, so no behavioral evidence "
          "exists either way");
    } else {
      out.rationale.push_back(
          "Sample executed but produced no telemetry; verdict inconclusive.");
      out.limitations.push_back(
          "the guest produced no behavioral telemetry despite the sample "
          "launch");
    }
    return out;
  }

  // ---- Pass 1: resolve the sample-launch anchor and its process identity. ----
  // The anchor is the agent's process.create of the staged sample, carrying the
  // VERIFIED details.sampleExecuted marker the guest sets at launch.
  // `agent.sample.received` (delivery) is NOT an execution anchor -- events
  // between delivery and launch are baseline. There is deliberately NO
  // "any process.create" fallback: an unrelated process cannot be promoted to
  // the sample by being the first/only create in the journal. Without the
  // marker the run has no anchor, ownership fails closed, and a negative verdict
  // is withheld for uncertainty rather than attributed to a guessed process.
  const EventRecord *launch = nullptr;
  auto considerLaunch = [&](const EventRecord &e) {
    if (launch == nullptr) {
      launch = &e;
      return;
    }
    if (!e.timestampUtc.empty() &&
        (launch->timestampUtc.empty() || e.timestampUtc < launch->timestampUtc)) {
      launch = &e;
    }
  };
  for (const auto &e : events) {
    if (Lower(e.category) != "process" || e.processId == 0) {
      continue;
    }
    const std::string a = Lower(e.action);
    if (!Has(a, "create") || Has(a, "failed")) {
      continue;
    }
    if (DetailIsTrue(e, "sampleExecuted")) {
      considerLaunch(e);
    }
  }

  const bool rootKnown = launch != nullptr;
  const uint32_t sampleRootPid = rootKnown ? launch->processId : 0;
  const std::string sampleLaunchTime = rootKnown ? launch->timestampUtc : "";
  std::string rootStartTime;
  std::string rootBootGeneration;
  std::string rootUser; // sample's identity user; used to scope user-profile coverage
  if (rootKnown) {
    if (const std::string *st = Detail(*launch, "startTime")) {
      rootStartTime = *st;
    }
    if (const std::string *bg = Detail(*launch, "bootGeneration")) {
      rootBootGeneration = *bg;
    }
    if (!launch->userName.empty()) {
      rootUser = launch->userName;
    } else if (const std::string *su = Detail(*launch, "sampleUser")) {
      rootUser = *su;
    } else if (const std::string *su2 = Detail(*launch, "user")) {
      rootUser = *su2;
    }
  }

  const auto bootMatches = [&](const EventRecord &e) {
    const auto *bg = Detail(e, "bootGeneration");
    return bg == nullptr || rootBootGeneration.empty() || *bg == rootBootGeneration;
  };
  // ---- Process instances and lifetimes (behavior-score-v4.1). ----
  // Identity is the process INSTANCE (pid + CAPTURED creation time), not a
  // numeric PID:
  //   * an unrelated process that reuses the root/child PID -- and its own
  //     descendants -- must not inherit sample membership;
  //   * a child is bound to the PARENT INSTANCE that existed at the child's
  //     captured creation time (a delayed observation of an older child is
  //     still the sample's child);
  //   * an already-created child keeps its membership after its parent exits;
  //   * events whose instance cannot be bound stay unknown (not attributed).
  struct PidInstances {
    std::vector<std::string> starts;               // known instance start times
    std::map<std::string, std::string> endByStart; // instance start -> end
    std::vector<std::string> endsUnbound;          // ends with no recorded start
  };
  std::map<uint32_t, PidInstances> lifetimes;
  const auto instanceStartOf = [](const EventRecord &e) -> std::string {
    if (const std::string *st = Detail(e, "startTime");
        st != nullptr && !st->empty()) {
      return *st;
    }
    return {};
  };
  for (const auto &e : events) {
    const std::string cat = Lower(e.category);
    if ((cat != "process" && cat != "crash") || e.processId == 0 ||
        e.timestampUtc.empty() || !bootMatches(e)) {
      continue;
    }
    const std::string a = Lower(e.action);
    const bool isEnd = Has(a, "stop") || Has(a, "exit") || Has(a, "terminat") ||
                       Has(a, "timeout") || Has(a, "crash");
    const bool isStart = !isEnd && (Has(a, "start") || Has(a, "create") ||
                                    Has(a, "spawn") || Has(a, "running"));
    if (!isEnd && !isStart) {
      continue;
    }
    PidInstances &L = lifetimes[e.processId];
    if (isStart) {
      const std::string st = instanceStartOf(e);
      const std::string start = st.empty() ? e.timestampUtc : st;
      if (std::find(L.starts.begin(), L.starts.end(), start) == L.starts.end()) {
        L.starts.push_back(start);
        std::sort(L.starts.begin(), L.starts.end());
      }
    } else {
      const std::string st = instanceStartOf(e);
      if (st.empty()) {
        L.endsUnbound.push_back(e.timestampUtc);
      } else {
        const auto it = L.endByStart.find(st);
        if (it == L.endByStart.end() || e.timestampUtc < it->second) {
          L.endByStart[st] = e.timestampUtc;
        }
      }
    }
  }
  // Fold unbound ends onto the latest known instance start at or before the end
  // time, so a stop that carries no startTime still closes the instance it
  // logically ended -- without touching any earlier/later instance of the PID.
  for (auto &entry : lifetimes) {
    for (const std::string &end : entry.second.endsUnbound) {
      const std::string *owner = nullptr;
      for (const std::string &s : entry.second.starts) {
        if (s <= end) {
          owner = &s;
        } else {
          break;
        }
      }
      if (owner != nullptr) {
        const auto it = entry.second.endByStart.find(*owner);
        if (it == entry.second.endByStart.end() || end < it->second) {
          entry.second.endByStart[*owner] = end;
        }
      }
    }
  }
  // The latest instance of `pid` that started at or before `ts`, or nullptr when
  // no known instance covers the moment.
  const auto latestInstanceAt = [&](uint32_t pid,
                                    const std::string &ts) -> const std::string * {
    const auto it = lifetimes.find(pid);
    if (it == lifetimes.end() || ts.empty()) {
      return nullptr;
    }
    const std::string *latest = nullptr;
    for (const std::string &s : it->second.starts) {
      if (s <= ts) {
        latest = &s;
      } else {
        break;
      }
    }
    return latest;
  };
  // True when any recorded end for `pid` is at or before `ts`.
  const auto anyEndAtOrBefore = [&](uint32_t pid, const std::string &ts) -> bool {
    const auto it = lifetimes.find(pid);
    if (it == lifetimes.end() || ts.empty()) {
      return false;
    }
    for (const auto &kv : it->second.endByStart) {
      if (kv.second <= ts) {
        return true;
      }
    }
    for (const std::string &end : it->second.endsUnbound) {
      if (end <= ts) {
        return true;
      }
    }
    return false;
  };

  // The root instance start: the anchor's captured startTime, or -- when it was
  // not captured -- the launch instant as a conservative instance start. The
  // "start time not captured" limitation is preserved separately.
  const bool rootStartCaptured = !rootStartTime.empty();
  const std::string rootInstanceStart =
      rootStartCaptured ? rootStartTime : sampleLaunchTime;

  // Sample instances: (pid, captured creation time) pairs established from the
  // verified anchor plus children admitted against a sample PARENT INSTANCE.
  std::set<std::pair<uint32_t, std::string>> sampleInstances;
  const auto isSampleInstance = [&](uint32_t pid, const std::string &start) {
    return sampleInstances.count({pid, start}) > 0;
  };
  // The root PID hosts exactly one sample instance per run. When the anchor did
  // not capture its creation time, membership falls back to "no recorded end at
  // or before the event"; a recorded end closes it definitively.
  const auto rootInstanceAliveAt = [&](const std::string &ts) {
    return !anyEndAtOrBefore(sampleRootPid, ts);
  };
  // True when the named instance has not recorded an end at or before `ts`.
  const auto instanceAliveAt = [&](uint32_t pid, const std::string &start,
                                   const std::string &ts) {
    const auto it = lifetimes.find(pid);
    if (it == lifetimes.end()) {
      return true;
    }
    const auto endIt = it->second.endByStart.find(start);
    return endIt == it->second.endByStart.end() || ts <= endIt->second;
  };

  if (rootKnown) {
    sampleInstances.insert({sampleRootPid, rootInstanceStart});
  }
  if (rootKnown && !rootInstanceStart.empty()) {
    PidInstances &RL = lifetimes[sampleRootPid];
    if (std::find(RL.starts.begin(), RL.starts.end(), rootInstanceStart) ==
        RL.starts.end()) {
      RL.starts.push_back(rootInstanceStart);
      std::sort(RL.starts.begin(), RL.starts.end());
    }
  }

  // Admit children by parent INSTANCE at the child's captured creation time.
  // Iterate to a fixed point so deeper generations join once their parent does.
  if (rootKnown) {
    bool changed = true;
    while (changed) {
      changed = false;
      for (const auto &e : events) {
        if (Lower(e.category) != "process" || e.processId == 0 || !bootMatches(e)) {
          continue;
        }
        const std::string captured = instanceStartOf(e);
        if (e.processId == sampleRootPid) {
          // Learn the root's real creation time when the anchor lacked it, as
          // long as no recorded end contradicts this instance.
          const auto *atLaunch = latestInstanceAt(sampleRootPid, sampleLaunchTime);
          if (!rootStartCaptured && !captured.empty() && atLaunch != nullptr &&
              *atLaunch == captured && captured <= sampleLaunchTime &&
              instanceAliveAt(sampleRootPid, captured, sampleLaunchTime)) {
            sampleInstances.insert({sampleRootPid, captured});
          }
          continue;
        }
        if (e.parentProcessId == 0) {
          continue;
        }
        // Parentage uses CAPTURED creation time; the observation time is a
        // fallback only when creation time was not captured.
        const std::string childCreated =
            captured.empty() ? e.timestampUtc : captured;
        if (childCreated.empty()) {
          // No creation time and no observation time at all. Admit only when
          // the parent has no recorded end (no evidence of a dead/reused
          // parent) and the child's own PID has no recorded end either; the
          // instance is recorded with an empty identity ("unknown creation
          // time") and later timestamp-less events for it are attributed only
          // while no end exists. A recorded end closes it (fail closed).
          const auto pit = lifetimes.find(e.parentProcessId);
          const bool parentEnded =
              pit != lifetimes.end() &&
              (!pit->second.endByStart.empty() || !pit->second.endsUnbound.empty());
          const bool parentIsRootUnknownTime =
              e.parentProcessId == sampleRootPid && !parentEnded;
          bool parentIsKnownSample =
              parentIsRootUnknownTime;
          if (!parentIsKnownSample) {
            for (const auto &key : sampleInstances) {
              if (key.first == e.parentProcessId) {
                parentIsKnownSample = true;
                break;
              }
            }
          }
          const auto cit = lifetimes.find(e.processId);
          const bool childEnded =
              cit != lifetimes.end() &&
              (!cit->second.endByStart.empty() || !cit->second.endsUnbound.empty());
          if (!parentIsKnownSample || childEnded) {
            continue;
          }
          // Insert only once: the fixed-point loop must terminate when the
          // event is re-examined on the next pass.
          const auto ins = sampleInstances.insert({e.processId, ""});
          if (!ins.second) {
            continue;
          }
          changed = true;
          continue;
        }
        if (isSampleInstance(e.processId, childCreated)) {
          continue;
        }
        // A new instance can legitimately reuse a PID. Its parent instance,
        // rather than previous users of that PID, determines membership.
        const std::string *cover =
            latestInstanceAt(e.parentProcessId, childCreated);
        bool parentIsSample = false;
        if (cover != nullptr && isSampleInstance(e.parentProcessId, *cover)) {
          // The parent instance must still be alive when the child is created.
          parentIsSample =
              instanceAliveAt(e.parentProcessId, *cover, childCreated);
        }
        if (!parentIsSample && cover == nullptr &&
            e.parentProcessId == sampleRootPid && !rootStartCaptured) {
          // The anchor's creation time was never captured, but the root is the
          // unique sample root until a recorded end closes it.
          parentIsSample = rootInstanceAliveAt(childCreated);
        }
        if (!parentIsSample) {
          continue;
        }
        const auto ins = sampleInstances.insert({e.processId, childCreated});
        if (!ins.second) {
          continue; // already admitted; keep the fixed-point loop terminating
        }
        changed = true;
      }
    }
  }

  // 1 = sample instance, 0 = known non-sample / unbound, for this event.
  const auto instanceCoveringSample = [&](const EventRecord &e) -> int {
    const std::string captured = instanceStartOf(e);
    if (!captured.empty()) {
      if (isSampleInstance(e.processId, captured)) {
        // The matched sample instance must still be alive at the event time
        // (an empty time cannot contradict a recorded end).
        return instanceAliveAt(e.processId, captured, e.timestampUtc) ? 1 : 0;
      }
      return 0;
    }
    if (e.timestampUtc.empty()) {
      // No time at all: attribute only when the PID has a sample instance and
      // no recorded end contradicts it; otherwise unknown (not attributed).
      bool hasSample = false;
      for (const auto &key : sampleInstances) {
        if (key.first == e.processId) {
          hasSample = true;
          break;
        }
      }
      if (!hasSample) {
        return -1;
      }
      const auto it = lifetimes.find(e.processId);
      if (it != lifetimes.end() &&
          (!it->second.endByStart.empty() || !it->second.endsUnbound.empty())) {
        return 0;
      }
      return 1;
    }
    const std::string *cover = latestInstanceAt(e.processId, e.timestampUtc);
    if (cover != nullptr) {
      if (isSampleInstance(e.processId, *cover)) {
        return instanceAliveAt(e.processId, *cover, e.timestampUtc) ? 1 : 0;
      }
      return 0;
    }
    if (e.processId == sampleRootPid) {
      return rootInstanceAliveAt(e.timestampUtc) ? 1 : 0;
    }
    // A child PID with sample instance(s) but no covering start: attribute only
    // when no recorded end contradicts the moment.
    bool hasSampleInstance = false;
    for (const auto &key : sampleInstances) {
      if (key.first == e.processId) {
        hasSampleInstance = true;
        break;
      }
    }
    if (!hasSampleInstance) {
      return 0;
    }
    return anyEndAtOrBefore(e.processId, e.timestampUtc) ? 0 : 1;
  };

  const auto inSampleSubtree = [&](const EventRecord &e) {
    if (!rootKnown || e.processId == 0 || !bootMatches(e)) {
      return false;
    }
    return instanceCoveringSample(e) == 1;
  };

  const auto classifyOwnership = [&](const EventRecord &e) {
    if (!rootKnown) {
      return Ownership::NoRoot;
    }
    if (e.processId != 0) {
      return inSampleSubtree(e) ? Ownership::ProcessAttributed
                                : Ownership::OtherProcess;
    }
    if (!e.timestampUtc.empty() && !sampleLaunchTime.empty() &&
        e.timestampUtc >= sampleLaunchTime) {
      return Ownership::TimeCorrelated;
    }
    return Ownership::Unowned;
  };

  // ---- Pass 2: collect signals --------------------------------------------
  int registryBaseline = 0;
  int registryDeletes = 0;
  int otherProcessMutations = 0;
  int noAnchorMutations = 0;
  bool unownedSecurityRelevant = false;
  int behavioralEvents = 0; // post-launch telemetry beyond the launch itself

  std::set<std::string> persistenceAttributed;
  std::set<std::string> persistenceTimeCorrelated;
  std::set<std::string> persistenceUnowned;
  std::set<std::string> stagingDrops;
  std::set<std::string> installWrites;
  std::set<std::string> timeCorrelatedDrops;
  std::set<std::string> unownedExecDrops;
  std::set<std::string> dataDrops;
  std::set<std::string> timeCorrelatedDataDrops;
  std::set<std::string> externalEndpoints;
  std::set<std::string> timeCorrelatedEndpoints;
  std::set<std::string> unownedEndpoints;
  std::set<std::string> suspiciousCmds;
  std::set<std::string> hijackLeads;
  std::set<std::string> writableModuleContext;
  std::set<std::string> persistenceTargets;
  std::set<std::string> dropTargets;
  int privEsc = 0;
  int approvedElevations = 0;
  int unknownElevations = 0;
  int otherMitre = 0;
  int sampleCrash = 0;
  int nonSampleCrash = 0;
  std::set<std::string> crashObservations;

  std::map<uint32_t, int> pidIntegrity;
  for (const auto &e : events) {
    if (Lower(e.category) == "process" && e.processId != 0 &&
        !e.integrityLevel.empty()) {
      pidIntegrity[e.processId] = IntegrityRank(e.integrityLevel);
    }
  }

  for (const auto &e : events) {
    // Pre-launch events are the boot/login baseline, not the sample's behavior.
    if (!sampleLaunchTime.empty() && !e.timestampUtc.empty() &&
        e.timestampUtc < sampleLaunchTime) {
      continue;
    }
    if (rootKnown && &e != launch) {
      const std::string cat = Lower(e.category);
      if (cat == "file" || cat == "registry" || cat == "process" ||
          cat == "network" || cat == "image" || cat == "crash") {
        ++behavioralEvents;
      }
    }
    const std::string cat = Lower(e.category);
    const std::string act = Lower(e.action);
    const std::string tgtL = Lower(e.target);
    const Ownership ownership = classifyOwnership(e);

    // --- Registry -----------------------------------------------------------
    if (cat == "registry") {
      if (IsRegistryDeleteAction(act)) {
        ++registryDeletes;
        continue; // removal: never "persistence established", zero weight
      }
      if (IsRegistryMutationAction(act)) {
        if (IsAutostartTarget(tgtL)) {
          const std::string key = tgtL.empty() ? act : tgtL;
          switch (ownership) {
          case Ownership::ProcessAttributed:
            persistenceAttributed.insert(key);
            break;
          case Ownership::TimeCorrelated:
            persistenceTimeCorrelated.insert(key);
            break;
          case Ownership::OtherProcess:
            ++otherProcessMutations;
            break;
          case Ownership::Unowned:
            persistenceUnowned.insert(key);
            unownedSecurityRelevant = true;
            break;
          case Ownership::NoRoot:
            ++noAnchorMutations;
            break;
          }
        } else if (ownership == Ownership::OtherProcess) {
          ++otherProcessMutations;
        } else if (ownership == Ownership::NoRoot) {
          ++noAnchorMutations;
        }
        continue;
      }
      if (IsRegistryReadAction(act)) {
        ++registryBaseline; // inventory, never scored as a write
      }
      continue;
    }

    // --- Files --------------------------------------------------------------
    if (cat == "file" && IsFileMutationAction(act)) {
      const std::string *ftPtr = Detail(e, "fileType");
      const std::string ft = ftPtr ? Lower(*ftPtr) : std::string();
      const bool exec = LooksExecutable(tgtL, ft);
      const std::string key = tgtL.empty() ? act : tgtL;
      if (!exec) {
        if (ft.empty() || ft == "(large, unhashed)") {
          continue; // no readable content: do not invent a data drop
        }
        if (ownership == Ownership::ProcessAttributed) {
          dataDrops.insert(key);
        } else if (ownership == Ownership::TimeCorrelated) {
          timeCorrelatedDataDrops.insert(key);
        }
        continue;
      }
      switch (ownership) {
      case Ownership::ProcessAttributed:
        if (IsStagingLocation(tgtL)) {
          stagingDrops.insert(key);
        } else {
          installWrites.insert(key);
        }
        break;
      case Ownership::TimeCorrelated:
        timeCorrelatedDrops.insert(key);
        break;
      case Ownership::OtherProcess:
        ++otherProcessMutations;
        break;
      case Ownership::Unowned:
        unownedExecDrops.insert(key);
        unownedSecurityRelevant = true;
        break;
      case Ownership::NoRoot:
        ++noAnchorMutations;
        break;
      }
      continue;
    }

    // --- Network ------------------------------------------------------------
    if (cat == "network" &&
        (Has(act, "connect") || Has(act, "connection") || Has(act, "dns") ||
         Has(act, "request") || Has(act, "http"))) {
      if (IsExternalEndpoint(e.target)) {
        switch (ownership) {
        case Ownership::ProcessAttributed:
          externalEndpoints.insert(tgtL);
          break;
        case Ownership::TimeCorrelated:
          timeCorrelatedEndpoints.insert(tgtL);
          break;
        case Ownership::Unowned:
          unownedEndpoints.insert(tgtL);
          unownedSecurityRelevant = true;
          break;
        case Ownership::OtherProcess:
        case Ownership::NoRoot:
          break;
        }
      }
      continue;
    }

    // --- Processes ----------------------------------------------------------
    if (cat == "process" || cat == "crash") {
      if (Has(act, "crash")) {
        std::string crashKey = e.timestampUtc + "|" + std::to_string(e.processId) +
            "|" + e.imagePath + "|" + e.target;
        for (const auto& field : e.details) crashKey += "|" + field.first + "=" + field.second;
        if (!crashObservations.insert(crashKey).second) continue;
        const bool sampleSelf =
            DetailIsTrue(e, "isSample") || Has(Lower(e.imagePath), "sample") ||
            Has(tgtL, "sample");
        if (sampleSelf) {
          ++sampleCrash;
        } else {
          ++nonSampleCrash;
        }
      }
      if ((Has(act, "start") || Has(act, "create") || Has(act, "spawn")) &&
          inSampleSubtree(e)) {
        const int childRank = IntegrityRank(e.integrityLevel);
        int parentRank = 0;
        if (const auto it = pidIntegrity.find(e.parentProcessId);
            it != pidIntegrity.end()) {
          parentRank = it->second;
        } else if (const std::string *parentLvl =
                       Detail(e, "parentIntegrityLevel")) {
          parentRank = IntegrityRank(*parentLvl);
        }
        const bool jumped = childRank >= 3 /* High or System */ &&
                            parentRank >= 1 && parentRank <= 2 /* Low/Medium */;
        if (jumped) {
          switch (ElevationConsentOf(e)) {
          case ElevationConsent::Approved:
            ++approvedElevations;
            break;
          case ElevationConsent::NotApproved:
            ++privEsc;
            break;
          case ElevationConsent::Unknown:
            ++unknownElevations;
            break;
          }
        }
      }
    }

    if (inSampleSubtree(e)) {
      if (const char *label = SuspiciousCommandLineLabel(e.commandLine)) {
        suspiciousCmds.insert(label);
      }
    }

    // --- Side-loaded / search-order-hijacked DLL ----------------------------
    // Three distinct evidence levels, never collapsed:
    //   (1) CONTEXT: a module loaded from a writable path (installers and
    //       self-extractors do this routinely) -- recorded, not scored.
    //   (2) LEAD: a search-order-relevant NAME in a writable/staging location.
    //       This is an investigation lead, not proof: a familiar filename does
    //       not establish replacement, a hijacked search order, or malicious
    //       module contents. Scored as a weak lead only.
    //   (3) VALIDATED HIJACK: a defined detector classification
    //       (details.hijackDetector naming a validated detector) PLUS concrete
    //       evidence references (details.hijackEvidence with at least one
    //       file/pair reference). Only this satisfies the high-specificity gate.
    // A bare tag, an alarming filename, or an unverified boolean annotation is
    // never a validated hijack finding.
    if (cat == "image" && Has(act, "load") && inSampleSubtree(e)) {
      const std::string *susp = Detail(e, "suspicion");
      const std::string suspL = susp ? Lower(*susp) : std::string();
      const std::string detector =
          Detail(e, "hijackDetector") ? Lower(*Detail(e, "hijackDetector"))
                                      : std::string();
      const std::string evidence =
          Detail(e, "hijackEvidence") ? *Detail(e, "hijackEvidence")
                                      : std::string();
      // No collector implements the claimed validation detectors. Arbitrary
      // event strings and unresolved references cannot establish a hijack.
      // Preserve them as leads until an evidence-validating detector exists.
      const bool hijackLead =
          (IsKnownShadowedDllName(tgtL) && IsStagingLocation(tgtL)) ||
          !detector.empty() || !evidence.empty();
      if (hijackLead) {
        hijackLeads.insert(tgtL.empty() ? act : tgtL);
      } else if (!suspL.empty() || !e.mitre.empty()) {
        writableModuleContext.insert(tgtL.empty() ? act : tgtL);
      }
    }

    // --- Any other MITRE-tagged behavior ------------------------------------
    // Registry/image are scored explicitly; require a real behavioral action
    // (never a read/baseline) and sample attribution. A MITRE tag alone can
    // never manufacture an action.
    if (!e.mitre.empty() && cat != "registry" && cat != "image" &&
        inSampleSubtree(e) && !IsRegistryReadAction(act) &&
        !Has(act, "observed")) {
      ++otherMitre;
    }
  }

  const int nPersistence = static_cast<int>(persistenceAttributed.size());
  const int nPersistenceTc =
      static_cast<int>(persistenceTimeCorrelated.size());
  const int nStagingDrops = static_cast<int>(stagingDrops.size());
  const int nInstallWrites = static_cast<int>(installWrites.size());
  const int nTcDrops = static_cast<int>(timeCorrelatedDrops.size());
  const int nDataDrops = static_cast<int>(dataDrops.size());
  const int nTcDataDrops = static_cast<int>(timeCorrelatedDataDrops.size());
  const int nExternal = static_cast<int>(externalEndpoints.size());
  const int nTcExternal = static_cast<int>(timeCorrelatedEndpoints.size());
  const int suspCmd = static_cast<int>(suspiciousCmds.size());
  const int nHijackLeads = static_cast<int>(hijackLeads.size());
  const int nWritableModules = static_cast<int>(writableModuleContext.size());

  // ---- Accumulate score + rationale, strongest signals first. ----
  if (nPersistence > 0) {
    const int w = std::min(35 * nPersistence, 105);
    out.score += w;
    std::string line = "Attributed persistence: " + std::to_string(nPersistence) +
                       " autostart/registry mutation(s) written by the sample "
                       "(+" +
                       std::to_string(w) + ").";
    std::string joined;
    int shown = 0;
    for (const auto &t : persistenceAttributed) {
      if (shown++ >= 3) {
        joined += ", ...";
        break;
      }
      joined += (joined.empty() ? "" : ", ") + t;
    }
    if (!joined.empty()) {
      line += " Targets: " + joined + ".";
    }
    out.rationale.push_back(line);
    out.positiveFindings.push_back(line);
  }
  if (nPersistenceTc > 0) {
    const int w = std::min(20 * nPersistenceTc, 60);
    out.score += w;
    std::string line =
        "Time-correlated registry mutation(s) in the sample's post-launch "
        "window: " +
        std::to_string(nPersistenceTc) + " (+" + std::to_string(w) +
        "). These deltas carry no process id; the correlation is temporal, not "
        "process attribution, and they cannot alone support a Malicious "
        "verdict.";
    out.rationale.push_back(line);
    out.positiveFindings.push_back(line);
  }
  const int nPersistenceUnowned =
      static_cast<int>(persistenceUnowned.size());
  if (nPersistenceUnowned > 0) {
    out.rationale.push_back(
        "Unattributed registry mutation(s) with no usable time relation: " +
        std::to_string(nPersistenceUnowned) +
        " -- not scored and not attributed to the sample.");
  }
  if (registryBaseline > 0) {
    out.rationale.push_back(
        "Registry baseline inventory recorded: " + std::to_string(registryBaseline) +
        " value observation(s). Inventory is not mutation evidence and is not "
        "scored.");
  }
  if (registryDeletes > 0) {
    out.rationale.push_back(
        "Registry deletion observed: " + std::to_string(registryDeletes) +
        " key/value removal(s). A deletion removes state; it does not "
        "establish persistence and is not scored as a persistence write. "
        "Deletion may still be relevant to tampering or cleanup when other "
        "evidence supports it.");
  }
  if (otherProcessMutations > 0) {
    out.rationale.push_back(
        std::to_string(otherProcessMutations) +
        " mutation(s) were attributed to a DIFFERENT process (outside the "
        "sample subtree) and excluded from the sample's score.");
  }
  if (noAnchorMutations > 0) {
    out.rationale.push_back(
        std::to_string(noAnchorMutations) +
        " mutation(s) were observed with no sample-launch anchor; ownership "
        "fails closed and they were not attributed to the sample.");
  }
  if (nStagingDrops > 0) {
    const int w = std::min(15 * nStagingDrops, 45);
    out.score += w;
    std::string joined;
    int shown = 0;
    for (const auto &t : stagingDrops) {
      if (shown++ >= 3) {
        joined += ", ...";
        break;
      }
      joined += (joined.empty() ? "" : ", ") + t;
    }
    std::string line =
        "Executable/script written by the sample to a user-writable staging "
        "path: " +
        std::to_string(nStagingDrops) + " (+" + std::to_string(w) + ").";
    if (!joined.empty()) {
      line += " Files: " + joined + ".";
    }
    out.rationale.push_back(line);
    out.positiveFindings.push_back(line);
  }
  if (nInstallWrites > 0) {
    const int w = std::min(5 * nInstallWrites, 10);
    out.score += w;
    out.rationale.push_back(
        "Application executable/DLL installation observed: " +
        std::to_string(nInstallWrites) +
        " file(s) written to an install location (+" + std::to_string(w) +
        "). Installation of an application's own files is a context "
        "observation; it is not, by itself, evidence of malware.");
  }
  if (nTcDrops > 0) {
    const int w = std::min(8 * nTcDrops, 24);
    out.score += w;
    std::string line =
        "Time-correlated executable/script write(s) in the sample's "
        "post-launch window: " +
        std::to_string(nTcDrops) + " (+" + std::to_string(w) +
        "). No process identity was captured, so this is temporal correlation, "
        "not process attribution.";
    out.rationale.push_back(line);
    out.positiveFindings.push_back(line);
  }
  const int nUnownedExec = static_cast<int>(unownedExecDrops.size());
  if (nUnownedExec > 0) {
    out.rationale.push_back(
        "Unattributed executable/script write(s) with no usable time relation: " +
        std::to_string(nUnownedExec) +
        " -- not scored and not attributed to the sample.");
  }
  if (privEsc > 0) {
    const int w = 20 * privEsc;
    out.score += w;
    out.rationale.push_back(
        "Unapproved elevation: " + std::to_string(privEsc) +
        " High/System-integrity child process(es) spawned from a Medium/Low "
        "parent where the recorded consent state was explicitly not approved "
        "(+" +
        std::to_string(w) +
        "). This is an unapproved privilege transition, not evidence of an "
        "exploitation mechanism -- the mechanism is not established by this "
        "observation, and it is not sample-attributable malice on its own.");
  }
  if (approvedElevations > 0) {
    out.rationale.push_back(
        "Elevated execution observed: " + std::to_string(approvedElevations) +
        " High/System child process(es) spawned from a Medium/Low parent with "
        "recorded policy approval -- recorded as a fact, not scored as an "
        "exploit.");
  }
  if (unknownElevations > 0) {
    out.rationale.push_back(
        "Elevated execution observed: " + std::to_string(unknownElevations) +
        " High/System child process(es) spawned from a Medium/Low parent; "
        "consent/approval state was NOT recorded for this launch -- recorded as "
        "a fact, not scored as escalation (missing approval information is not "
        "evidence of unauthorized privilege escalation).");
  }

  if (nHijackLeads > 0) {
    const int w = std::min(5 * nHijackLeads, 15);
    out.score += w;
    std::string joined;
    int shown = 0;
    for (const auto &m : hijackLeads) {
      if (shown++ >= 3) {
        joined += ", ...";
        break;
      }
      joined += (joined.empty() ? "" : ", ") + m;
    }
    out.rationale.push_back(
        "DLL name/location lead(s): " + std::to_string(nHijackLeads) +
        " search-order-relevant module name(s) loaded from a writable/staging "
        "path (" +
        joined + ") (+" + std::to_string(w) +
        "). Recorded as an investigation lead, NOT a confirmed hijack: a "
        "familiar DLL name in a writable path does not establish replacement, "
        "a hijacked search order, or malicious module contents.");
  }
  if (nWritableModules > 0) {
    std::string joined;
    int shown = 0;
    for (const auto &m : writableModuleContext) {
      if (shown++ >= 3) {
        joined += ", ...";
        break;
      }
      joined += (joined.empty() ? "" : ", ") + m;
    }
    out.rationale.push_back(
        "Module(s) loaded from a writable, non-system path: " +
        std::to_string(nWritableModules) + " (" + joined +
        "). Recorded as a context observation, not scored: a writable path "
        "alone is not a search-order hijack.");
  }
  if (nExternal > 0) {
    const int w = 20 + std::min(nExternal - 1, 5) * 8;
    out.score += w;
    std::string joined;
    int shown = 0;
    for (const auto &t : externalEndpoints) {
      if (shown++ >= 3) {
        joined += ", ...";
        break;
      }
      joined += (joined.empty() ? "" : ", ") + t;
    }
    std::string line =
        "Sample-attributed outbound network egress to " +
        std::to_string(nExternal) + " external endpoint(s) (non-loopback, "
        "non-RFC1918) (+" +
        std::to_string(w) + "). Endpoints: " + joined + ".";
    out.rationale.push_back(line);
    out.positiveFindings.push_back(line);
  }
  if (nTcExternal > 0) {
    const int w = std::min(10 * nTcExternal, 20);
    out.score += w;
    out.rationale.push_back(
        "Time-correlated external network connection(s) with no captured "
        "process id: " +
        std::to_string(nTcExternal) + " (+" + std::to_string(w) +
        "); temporal correlation only.");
  }
  const int nUnownedExternal = static_cast<int>(unownedEndpoints.size());
  if (nUnownedExternal > 0) {
    out.rationale.push_back(
        "Unattributed external connection(s) with no usable time relation: " +
        std::to_string(nUnownedExternal) +
        " -- not scored and not attributed to the sample.");
  }
  if (suspCmd > 0) {
    const int w = 15 * suspCmd;
    out.score += w;
    std::string joined;
    for (const auto &s : suspiciousCmds) {
      joined += (joined.empty() ? "" : ", ") + s;
    }
    std::string line = "Suspicious command line(s): " + joined + " (+" +
                       std::to_string(w) + ").";
    out.rationale.push_back(line);
    out.positiveFindings.push_back(line);
  }
  if (sampleCrash > 0) {
    const int w = 8;
    out.score += w;
    out.rationale.push_back(
        "Sample process crashed -- may indicate exploit/packer failure or "
        "instability (+" +
        std::to_string(w) + ").");
  }
  if (nonSampleCrash > 0) {
    out.rationale.push_back(
        std::to_string(nonSampleCrash) +
        " distinct non-sample crash observation(s). Context only, not scored: "
        "a crash alone does not establish injection or sample causation.");
  }
  if (nDataDrops > 0) {
    const int w = std::min(3 * nDataDrops, 12);
    out.score += w;
    out.rationale.push_back("Dropped " + std::to_string(nDataDrops) +
                            " non-executable data file(s) (+" +
                            std::to_string(w) + ").");
  }
  if (nTcDataDrops > 0) {
    const int w = std::min(2 * nTcDataDrops, 6);
    out.score += w;
    out.rationale.push_back(
        "Time-correlated non-executable data write(s): " +
        std::to_string(nTcDataDrops) + " (+" + std::to_string(w) + ").");
  }
  if (otherMitre > 0) {
    const int w = std::min(otherMitre, 4) * 6;
    out.score += w;
    std::string line =
        std::to_string(otherMitre) +
        " additional MITRE-tagged behavior(s) attributed to the sample (+" +
        std::to_string(w) + ").";
    out.rationale.push_back(line);
    out.positiveFindings.push_back(line);
  }

  const bool richBehavior =
      out.score > 0 || registryBaseline > 0 || registryDeletes > 0 ||
      nPersistenceUnowned > 0 || nUnownedExec > 0 || nUnownedExternal > 0;

  // ---- Map score -> verdict. ----
  //   >= 60 : two strong signals, or one strong + corroboration -> Malicious
  //           (>= 90 when the sample carries an Authenticode signature)
  //   >= 20 : at least one noteworthy signal                    -> Suspicious
  //   else  : nothing noteworthy observed                       -> Clean
  const int maliciousThreshold = 60;
  if (out.score >= maliciousThreshold) {
    out.verdict = Verdict::Malicious;
  } else if (out.score >= 20) {
    out.verdict = Verdict::Suspicious;
  } else {
    out.verdict = Verdict::Clean;
  }

  // Malicious requires SAMPLE-ATTRIBUTABLE and HIGH-SPECIFICITY evidence.
  // Attribution alone is not enough, and neither is a count of generic
  // categories: an ordinary updater legitimately writes a Run key, drops a
  // temporary helper, and contacts an update endpoint. Confirmation requires a
  // high-specificity signal -- an anomalous command line, a verified DLL
  // search-order hijack, or other attributed MITRE-tagged behavior. Adding an
  // installation-directory write must change neither direction of the verdict.
  const bool highSpecificity = suspCmd > 0 || otherMitre > 0;
  const int genericCategories = (nStagingDrops > 0 ? 1 : 0) +
                                (nExternal > 0 ? 1 : 0);
  // Installation context changes the EXPLANATION (a program installing its own
  // files under Program Files is context), never the confirmation bar.
  const bool looksLikeOrdinaryInstall = nInstallWrites > 0;
  const bool attributableMalice = highSpecificity;
  if (out.verdict == Verdict::Malicious && !attributableMalice) {
    out.verdict = Verdict::Suspicious;
    if (looksLikeOrdinaryInstall) {
      out.rationale.push_back(
          "Capped at Suspicious: the run installed the application's own files "
          "under an install location and showed only generic drop/connection "
          "activity. That is the shape of an ordinary installer; confirming "
          "malware in this shape requires a high-specificity signal (anomalous "
          "command line, verified DLL hijack, or attributed MITRE behavior), not "
          "a score crossed by ordinary actions.");
    } else if (nPersistence > 0 && (nStagingDrops > 0 || nExternal > 0)) {
      out.rationale.push_back(
          "Capped at Suspicious: an attributed Run-key write plus generic "
          "staging/connection activity is the shape of an ordinary auto-updater "
          "(self-registration, a temporary helper, an update endpoint), not "
          "confirmation of malware. Confirming malware in this shape requires "
          "high-specificity evidence (anomalous command line, verified DLL "
          "hijack, or another attributed MITRE behavior); counting generic "
          "categories is not such evidence.");
    } else if (nStagingDrops > 0 || nExternal > 0) {
      out.rationale.push_back(
          "Capped at Suspicious: the score is driven by generic drop/connection "
          "activity (staged file writes and/or external endpoint connections) "
          "without a high-specificity signal (anomalous command line, verified "
          "DLL hijack, attributed MITRE behavior). Ordinary installers and "
          "updaters do all of these; repeating one ordinary category is not "
          "confirmation of malware.");
    } else {
      out.rationale.push_back(
          "Capped at Suspicious: the score is driven only by attributed "
          "persistence / installation context / time-correlated observations; no "
          "sample-attributable high-specificity malice (suspicious command line, "
          "verified DLL hijack, or other attributed MITRE-tagged behavior) "
          "corroborated it.");
    }
  }

  // ---- Evidence-sufficiency gate (behavior-score-v4). ----
  // A reassuring negative requires an observation that could have seen the
  // behavior it is denying. Coverage limits WITHHOLD a negative verdict; they
  // never erase a positive finding that other evidence supports.
  const bool declaredEnd =
      summary.completed || summary.timedOut || summary.crashed;
  const bool interrupted = summary.started && !declaredEnd;
  std::vector<std::string> flipLimits; // limits that withhold a negative verdict
  std::vector<std::string> noteLimits; // limits that qualify any verdict

  if (interrupted) {
    flipLimits.push_back(
        "the run ended without a completion signal (interrupted, or the worker "
        "was lost before the declared end)");
  }
  if (!summary.guestAgentConnected) {
    flipLimits.push_back(
        "the guest telemetry channel never confirmed a healthy agent, so "
        "collector coverage is unverified");
  }
  if (!rootKnown) {
    flipLimits.push_back(
        "no sample-launch anchor (process.create) was recorded, so events "
        "could not be attributed to the sample");
  }
  if (rootKnown && behavioralEvents == 0) {
    flipLimits.push_back(
        "the journal contains no behavioral telemetry beyond the sample "
        "launch");
  }
  // G4 coverage: a reassuring negative requires evidence that the sensors which
  // would have seen the denied behavior were actually running and not losing
  // records. Unknown coverage is NOT healthy coverage.
  if (summary.sensorCoverage.empty()) {
    flipLimits.push_back(
        "no per-sensor coverage record was received, so no collector's health or "
        "loss is established");
  } else {
    bool anyLoss = false;
    bool anyUnhealthy = false;
    std::string detail;
    for (const auto &s : summary.sensorCoverage) {
      if (!s.supported || !s.healthy || s.samples == 0) {
        // Unsupported, last collection failed, or the collector never completed
        // a single successful cycle -- all mean "not instrumented", never
        // "nothing happened".
        anyUnhealthy = true;
      }
      if (s.dropped > 0) {
        // A drop count is loss whether or not the exact total is known.
        anyLoss = true;
      }
      if (!s.lossKnown && s.dropped == 0) {
        // The collector cannot account for its own drops: the recorded zero is a
        // lower bound, so loss is UNKNOWN (not absent).
        anyLoss = true;
        if (s.note.empty()) {
          detail += (detail.empty() ? "" : "; ") + s.sensor +
                    ": loss unknown (collector cannot account for drops)";
        }
      }
      if (!s.note.empty()) {
        detail += (detail.empty() ? "" : "; ") + s.sensor + ": " + s.note;
      }
    }
    if (anyLoss) {
      flipLimits.push_back(
          "at least one sensor reported (or could not rule out) dropped records, "
          "so the observation is known to be lossy");
    }
    if (anyUnhealthy) {
      flipLimits.push_back(
          "at least one sensor was unsupported, uncollected, or reported a "
          "failed collection");
    }
    if (!detail.empty()) {
      noteLimits.push_back("sensor coverage notes: " + detail);
    }
    // Required capability coverage (v3): a reassuring negative must be able to
    // deny behavior in every category the scorer considered. One healthy
    // collector (e.g. registry) says nothing about processes, files, modules, or
    // network, so a missing required collector withholds the negative.
    static const char *kRequiredSensors[] = {"process", "network", "registry",
                                             "filesystem", "image"};
    for (const char *required : kRequiredSensors) {
      bool present = false;
      for (const auto &s : summary.sensorCoverage) {
        if (s.sensor == required) {
          present = true;
          break;
        }
      }
      if (!present) {
        flipLimits.push_back(
            std::string("no coverage record for the ") + required +
            " collector, so behavior in that category was not shown to be "
            "observable");
      }
    }
    // User-scope enforcement (v3): file and registry coverage resolves from a
    // user profile/hive. Coverage collected for a DIFFERENT user (or with no
    // declared user) cannot deny the sample user's file/registry behavior. A
    // collector that explicitly declares system scope is machine-wide and is
    // exempt from the identity match.
    for (const auto &s : summary.sensorCoverage) {
      const bool userScopedData =
          s.sensor == "filesystem" || s.sensor == "registry";
      if (!userScopedData || s.scope == "system") {
        continue;
      }
      if (s.targetUser.empty()) {
        flipLimits.push_back(
            "the " + s.sensor +
            " collector did not record which user profile it observed, so its "
            "coverage cannot be matched to the sample's user");
      } else if (rootKnown && rootUser.empty()) {
        flipLimits.push_back(
            "the sample's user identity was not recorded, so " + s.sensor +
            " coverage for '" + s.targetUser +
            "' could not be verified as the sample's own profile");
      } else if (!rootUser.empty() &&
                 !EqualInsensitive(s.targetUser, rootUser)) {
        flipLimits.push_back(
            s.sensor + " coverage observed '" + s.targetUser +
            "', not the sample's user '" + rootUser +
            "', so the sample's own profile/hive was not monitored");
      }
    }
  }
  if (summary.coverageIncomplete) {
    flipLimits.push_back(
        "the run's coverage summary is marked incomplete");
  }
  if (unownedSecurityRelevant) {
    flipLimits.push_back(
        "security-relevant mutation(s) carried no process identity and no "
        "usable time relation, so they could not be attributed to the sample");
  }
  if (rootKnown && rootStartTime.empty()) {
    noteLimits.push_back(
        "the sample root's process start time was not captured, so PID reuse "
        "could not be excluded from attribution");
  }
  if (nPersistenceTc > 0 || nTcDrops > 0 || nTcExternal > 0 ||
      nTcDataDrops > 0) {
    noteLimits.push_back(
        "poll-diff telemetry carries no process id for file/registry deltas; "
        "those observations are time-correlated, not process-attributed");
  }

  if (!flipLimits.empty()) {
    std::string joined;
    for (const auto &l : flipLimits) {
      joined += (joined.empty() ? "" : "; ") + l;
    }
    const bool positiveEvidence = out.verdict == Verdict::Suspicious ||
                                  out.verdict == Verdict::Malicious;
    if (!positiveEvidence) {
      out.verdict = Verdict::Unknown;
      out.insufficientEvidence = true;
      out.rationale.push_back(
          "VERDICT WITHHELD -- insufficient observation: " + joined +
          ". Absence of observed behavior under incomplete coverage is not "
          "evidence of benignity.");
    } else {
      out.rationale.push_back(
          "Partial-coverage note: observation was incomplete (" + joined +
          "); the positive findings above stand, but they describe only what "
          "was captured before/while coverage was limited.");
    }
  }
  for (auto &l : flipLimits) {
    out.limitations.push_back(std::move(l));
  }
  for (auto &l : noteLimits) {
    out.limitations.push_back(std::move(l));
  }

  // ---- Timeout false-positive guard. ----
  // Hitting the time budget is NOT itself a malicious act. If the run merely
  // timed out without accumulating real behavior, say so explicitly and keep
  // the Clean verdict -- this is the documented "benign sample ran to timeout
  // looks Malicious" regression, killed here.
  if (summary.timedOut && !out.insufficientEvidence) {
    if (!richBehavior) {
      out.rationale.push_back(
          "Run reached its time budget without exhibiting malicious behavior; "
          "timeout alone is not a malicious signal -> Clean.");
    } else {
      out.rationale.push_back(
          "Run reached its time budget; verdict is from observed behavior "
          "above, not from the timeout.");
    }
  }

  if (out.verdict == Verdict::Clean && out.rationale.empty()) {
    out.rationale.push_back(
        "No malicious behavior observed in the detonation window. Note: Clean "
        "reflects what was seen during this run, not a proof of benignity "
        "(low-and-slow or environment-gated malware may stay dormant).");
  } else if (out.verdict == Verdict::Clean && richBehavior) {
    out.rationale.push_back("Observed activity scored below the suspicious "
                            "threshold -> Clean.");
  }

  return out;
}

} // namespace antimal
