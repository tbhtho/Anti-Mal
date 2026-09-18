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
  // rundll32 abuse. NOTE: do NOT match a bare "shell32" — `rundll32
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

} // namespace

// Signal weights. Tuned so a single strong signal lands in Suspicious and two
// strong signals (or one strong + corroboration) push into Malicious, while a
// lone weak signal stays Suspicious-at-most. Thresholds below.
//
//   persistence (per event, MITRE-confirmed)        +35
//   dropped executable / script (per event)         +30
//   privilege escalation (child elevated vs parent) +35
//   DLL side-load / search-order hijack (first)     +25
//   DLL side-load / search-order hijack (each more)  +8 (capped)
//   external network egress (first endpoint)        +20
//   external network egress (each extra endpoint)    +8 (capped)
//   suspicious command line (per distinct technique) +15
//   sample process self-crash                        +8
//   crash of a non-sample process                    +6 (capped)
//   dropped data file (non-exec, per event)          +5 (capped)
//   other MITRE-tagged behavior (per event)          +6 (capped)
//   rich executed behavior present                   +5 (context, not a tell)
BehaviorScore ScoreSandboxBehavior(const DynamicRunSummary &summary,
                                   const std::vector<EventRecord> &events,
                                   bool sampleSigned) {
  BehaviorScore out;

  // Nothing ran (gated/healthcheck) or no telemetry at all -> inconclusive.
  if (!summary.sampleExecuted || events.empty()) {
    out.verdict = Verdict::Unknown;
    // Consistent with the evidence-sufficiency contract: a run with nothing to
    // judge is INSUFFICIENT EVIDENCE, not a negative finding. Saying so lets
    // every consumer label it honestly instead of implying "nothing happened".
    out.insufficientEvidence = true;
    if (!summary.sampleExecuted) {
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

  int persistence = 0;
  int unattributedPersistence = 0; // registry deltas carry no PID (poll-diff)
  int exeDrops = 0;
  int dataDrops = 0;
  int privEsc = 0;
  int approvedElevations = 0; // elevated execution approved by policy: a FACT
  int unknownElevations = 0;  // elevated execution, consent not recorded: a FACT
  int otherMitre = 0;
  int sampleCrash = 0;
  int nonSampleCrash = 0;
  std::set<std::string> externalEndpoints;
  std::set<std::string> suspiciousCmds; // distinct technique labels
  std::set<std::string> persistenceTargets;
  std::set<std::string> dropTargets;
  std::set<std::string> suspiciousModules; // distinct side-loaded/hijacked DLLs

  // First pass: map each PID to the integrity level the telemetry observed for
  // it, so the privilege-escalation check can resolve a child's PARENT integrity
  // from the actual event stream (parents may appear before or after children).
  // This makes the privEsc signal live on real runs -- previously it depended on
  // a details["parentIntegrityLevel"] field that production telemetry never set.
  std::map<uint32_t, int> pidIntegrity;
  for (const auto &e : events) {
    if (Lower(e.category) == "process" && e.processId != 0 &&
        !e.integrityLevel.empty()) {
      pidIntegrity[e.processId] = IntegrityRank(e.integrityLevel);
    }
  }

  // The sandbox's own boot/login churns ~100+ autostart-registry keys, writes
  // files, and crash-loops the shell BEFORE the sample ever runs -- that is
  // baseline, not the sample's behavior. (registry/file deltas carry no PID, so a
  // time gate is the available attribution.) Anchor on the moment the in-guest
  // agent launched the staged sample (`process.create` / `sample.received`) and
  // score ONLY events at/after it. ISO-8601 UTC timestamps compare
  // lexicographically. When no anchor is found, the gate is a no-op (count all).
  std::string sampleExecTime;
  uint32_t sampleRootPid = 0;
  for (const auto &e : events) {
    const std::string a = Lower(e.action);
    if ((a == "process.create" || Has(a, "sample.received")) &&
        !e.timestampUtc.empty() &&
        (sampleExecTime.empty() || e.timestampUtc < sampleExecTime)) {
      sampleExecTime = e.timestampUtc;
    }
    // The agent's process.create of the staged sample is the subtree root.
    if (a == "process.create" && e.processId != 0 && sampleRootPid == 0) {
      sampleRootPid = e.processId;
    }
  }

  // The sample's process subtree (root + descendants via parentProcessId).
  // Process-based signals (suspicious command lines, privilege escalation) are
  // restricted to it so the OS's OWN LOLBins -- rundll32/regsvr32/mshta/... that
  // Windows boot/login/shell run constantly and legitimately -- cannot
  // masquerade as the sample's malice. When the root is unknown (no
  // process.create), the subtree is empty and the restriction is a no-op.
  std::set<uint32_t> sampleSubtree;
  if (sampleRootPid != 0) {
    sampleSubtree.insert(sampleRootPid);
    bool changed = true;
    while (changed) {
      changed = false;
      for (const auto &e : events) {
        if (Lower(e.category) == "process" && e.processId != 0 &&
            e.parentProcessId != 0 && sampleSubtree.count(e.parentProcessId) &&
            sampleSubtree.insert(e.processId).second) {
          changed = true;
        }
      }
    }
  }
  const auto inSampleSubtree = [&](uint32_t pid) {
    return sampleSubtree.empty() || sampleSubtree.count(pid) != 0;
  };

  for (const auto &e : events) {
    // Skip the pre-execution boot/login baseline.
    if (!sampleExecTime.empty() && !e.timestampUtc.empty() &&
        e.timestampUtc < sampleExecTime) {
      continue;
    }
    const std::string cat = Lower(e.category);
    const std::string act = Lower(e.action);
    const std::string tgtL = Lower(e.target);

    // --- Persistence: a registry write that the telemetry already classified
    // as persistence (MITRE set) OR that lands on a known autostart location.
    if (cat == "registry") {
      const bool mitreTagged = !e.mitre.empty();
      const bool autostart =
          Has(tgtL, "currentversion\\run") || Has(tgtL, "\\runonce") ||
          Has(tgtL, "winlogon") || Has(tgtL, "services\\") ||
          Has(tgtL, "\\run\\") || EndsWith(tgtL, "\\run");
      if (mitreTagged || autostart) {
        if (persistenceTargets.insert(tgtL.empty() ? act : tgtL).second) {
          ++persistence;
          // Poll-diff registry telemetry carries no owning PID, so these
          // writes are not attributed to the sample. Still a signal, but the
          // rationale must not imply the sample authored them.
          if (e.processId == 0) {
            ++unattributedPersistence;
          }
        }
      }
    }

    // --- Dropped files: an executable/script drop is strong; a data drop is
    // weak. Prefer the magic-byte fileType the telemetry recorded.
    if (cat == "file" &&
        (Has(act, "create") || Has(act, "write") || Has(act, "drop"))) {
      const std::string *ftPtr = Detail(e, "fileType");
      const std::string ft = ftPtr ? Lower(*ftPtr) : std::string();
      const bool execByType =
          ft == "pe" || ft == "elf" || ft == "macho" || ft == "script" ||
          ft == "php";
      const bool execByExt = EndsWith(tgtL, ".exe") || EndsWith(tgtL, ".dll") ||
                             EndsWith(tgtL, ".scr") || EndsWith(tgtL, ".sys") ||
                             EndsWith(tgtL, ".ps1") || EndsWith(tgtL, ".bat") ||
                             EndsWith(tgtL, ".cmd") || EndsWith(tgtL, ".vbs") ||
                             EndsWith(tgtL, ".js") || EndsWith(tgtL, ".hta") ||
                             EndsWith(tgtL, ".jar") || EndsWith(tgtL, ".msi");
      const std::string key = tgtL.empty() ? act : tgtL;
      if (execByType || execByExt) {
        if (dropTargets.insert(key).second) {
          ++exeDrops;
        }
      } else if (!ft.empty() && ft != "(large, unhashed)") {
        // A concrete, readable, non-exec drop (data, zip, document, ...).
        if (dropTargets.insert("data:" + key).second) {
          ++dataDrops;
        }
      }
    }

    // --- Network: outbound connection to a genuinely external endpoint,
    // ATTRIBUTED to the sample's process subtree. The TCP telemetry carries the
    // owning PID (GetExtendedTcpTable TCP_TABLE_OWNER_PID -> EventRecord.processId),
    // so we exclude Windows' own concurrent background egress (telemetry, NTP,
    // Update, NCSI) that the post-execution time gate can't filter -- only the
    // sample (or a process it spawned) making external egress is a malice signal.
    // Same subtree discipline as the suspicious-command-line / privesc signals.
    if (cat == "network" &&
        (Has(act, "connect") || Has(act, "connection") || Has(act, "dns") ||
         Has(act, "request") || Has(act, "http")) &&
        inSampleSubtree(e.processId)) {
      if (IsExternalEndpoint(e.target)) {
        externalEndpoints.insert(tgtL);
      }
    }

    // --- Privilege transition: a child process whose integrity level is High/
    // System while its recorded parent integrity was Medium/Low. Three consent
    // states, deliberately distinct:
    //   Approved    -> elevated execution: a recorded FACT, never scored.
    //   NotApproved -> an explicit refusal was overridden: escalation signal.
    //   Unknown     -> consent was simply not recorded: still a FACT (recorded
    //                  for the analyst) but NEVER scored, because absence of
    //                  approval information is not evidence of unauthorized
    //                  escalation.
    if (cat == "process" &&
        (Has(act, "start") || Has(act, "create") || Has(act, "spawn"))) {
      const int childRank = IntegrityRank(e.integrityLevel);
      // Parent integrity: prefer the live event stream (the parent PID's own
      // observed level), fall back to an explicit details field if present.
      int parentRank = 0;
      if (const auto it = pidIntegrity.find(e.parentProcessId);
          it != pidIntegrity.end()) {
        parentRank = it->second;
      } else if (const std::string *parentLvl = Detail(e, "parentIntegrityLevel")) {
        parentRank = IntegrityRank(*parentLvl);
      }
      const bool jumped = childRank >= 3 /* High or System */ &&
                          parentRank >= 1 && parentRank <= 2 /* Low or Medium */;
      if (jumped && inSampleSubtree(e.processId)) {
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

    // --- Suspicious command lines (loader / LOLBins). One per distinct tell,
    // and ONLY for the sample's own process subtree -- Windows runs rundll32 /
    // regsvr32 / mshta legitimately during boot/login, which would otherwise
    // corroborate a Malicious verdict for a benign sample.
    if (inSampleSubtree(e.processId)) {
      if (const char *label = SuspiciousCommandLineLabel(e.commandLine)) {
        suspiciousCmds.insert(label);
      }
    }

    // --- Crashes. A non-sample crash is weak (could be instability); the
    // sample crashing itself is noted modestly (could be a packer/exploit).
    // The WER decoder emits these with category="crash"; the process collector
    // can also surface "process.crash" under category="process" -- accept both.
    if ((cat == "process" || cat == "crash") && Has(act, "crash")) {
      const std::string *isSample = Detail(e, "isSample");
      const bool sampleSelf =
          (isSample && (*isSample == "true" || *isSample == "1")) ||
          Has(Lower(e.imagePath), "sample") || Has(tgtL, "sample");
      if (sampleSelf) {
        ++sampleCrash;
      } else {
        ++nonSampleCrash;
      }
    }

    // --- Side-loaded / search-order-hijacked DLL: an image.load the telemetry
    // flagged as loaded from a writable, non-system path (details["suspicion"]
    // set, MITRE-tagged). De-duped by module path so a repeated load of the same
    // hijacked DLL counts once.
    if (cat == "image" && Has(act, "load") && inSampleSubtree(e.processId)) {
      const std::string *susp = Detail(e, "suspicion");
      if ((susp && !susp->empty()) || !e.mitre.empty()) {
        suspiciousModules.insert(tgtL.empty() ? act : tgtL);
      }
    }

    // --- Any other MITRE-tagged behavior we did not already count above.
    // Registry persistence and suspicious image loads are scored explicitly, so
    // exclude both categories here to avoid double-counting. Subtree-gated so an
    // OS process's MITRE-tagged behavior can't corroborate the sample (same
    // discipline as the egress / cmdline / privesc / side-load signals).
    if (!e.mitre.empty() && cat != "registry" && cat != "image" &&
        inSampleSubtree(e.processId)) {
      ++otherMitre;
    }
  }

  const int extNet = static_cast<int>(externalEndpoints.size());
  const int suspCmd = static_cast<int>(suspiciousCmds.size());
  const int suspMod = static_cast<int>(suspiciousModules.size());

  // ---- Accumulate score + rationale, strongest signals first. ----
  if (persistence > 0) {
    // Capped like every other signal so even a residual burst of autostart
    // writes can't run away with the score (the first ~3 mechanisms is plenty
    // to call persistence; real malware rarely needs more).
    const int w = std::min(35 * persistence, 105);
    out.score += w;
    std::string line;
    if (unattributedPersistence == persistence) {
      // Poll-diff registry telemetry carries no owning PID: these writes are
      // observed, but NOT established as the sample's persistence.
      line = "Autostart/registry-run writes observed: " +
             std::to_string(persistence) + " (+" + std::to_string(w) +
             "). Registry deltas carry no process id, so these writes are NOT "
             "attributed to the sample and do NOT establish sample persistence; "
             "they cannot alone support a Malicious verdict.";
    } else {
      line = "Persistence established: " + std::to_string(persistence) +
             " autostart/registry-run write(s) attributed to the sample (+" +
             std::to_string(w) + ").";
      if (unattributedPersistence > 0) {
        line += " " + std::to_string(unattributedPersistence) +
                " further write(s) carry no process id (unattributed).";
      }
    }
    out.rationale.push_back(std::move(line));
  }
  if (exeDrops > 0) {
    const int w = 30 * exeDrops;
    out.score += w;
    out.rationale.push_back(
        "Dropped executable/script payload: " + std::to_string(exeDrops) +
        " file(s) (+" + std::to_string(w) + ").");
  }
  if (privEsc > 0) {
    // An explicit "not approved" consent record is an UNAPPROVED ELEVATION --
    // an application-grant fact. It is deliberately NOT described as an
    // exploitation mechanism: this observation shows the privilege transition,
    // not how it was obtained (a legitimately elevated helper, a service, or an
    // exploit all look identical here).
    const int w = 20 * privEsc;
    out.score += w;
    out.rationale.push_back(
        "Unapproved elevation: " + std::to_string(privEsc) +
        " High/System-integrity child process(es) spawned from a Medium/Low "
        "parent where the recorded consent state was explicitly not approved "
        "(+" + std::to_string(w) +
        "). This is an unapproved privilege transition, not evidence of an "
        "exploitation mechanism -- the mechanism is not established by this "
        "observation, and it is not sample-attributable malice on its own.");
  }
  if (approvedElevations > 0) {
    // Elevated execution the run policy approved is a FACT about the run, not
    // an exploit signal. Scoring it as escalation would turn every approved
    // UAC prompt into "malice" -- exactly the false certainty F1 flagged.
    out.rationale.push_back(
        "Elevated execution observed: " + std::to_string(approvedElevations) +
        " High/System child process(es) spawned from a Medium/Low parent with "
        "recorded policy approval -- recorded as a fact, not scored as an "
        "exploit.");
  }
  if (unknownElevations > 0) {
    // Consent state was simply never recorded for this elevation. That is an
    // information gap, not evidence of an unauthorized transition: record the
    // fact and make the gap visible instead of scoring it.
    out.rationale.push_back(
        "Elevated execution observed: " + std::to_string(unknownElevations) +
        " High/System child process(es) spawned from a Medium/Low parent; "
        "consent/approval state was NOT recorded for this launch -- recorded as "
        "a fact, not scored as escalation (missing approval information is not "
        "evidence of unauthorized privilege escalation).");
    out.limitations.push_back(
        "elevation consent state was not recorded for " +
        std::to_string(unknownElevations) +
        " privilege transition(s); elevated execution is reported as a fact "
        "without an attribution conclusion");
  }
  if (suspMod > 0) {
    // First side-loaded/hijacked DLL is moderate; each additional one adds less,
    // capped so a process loading many DLLs from one writable dir can't run away
    // with the score. Names the offending module(s) for the analyst.
    const int w = 25 + std::min(suspMod - 1, 5) * 8;
    out.score += w;
    std::string joined;
    int shown = 0;
    for (const auto &m : suspiciousModules) {
      if (shown++ >= 3) {
        joined += ", ...";
        break;
      }
      joined += (joined.empty() ? "" : ", ") + m;
    }
    out.rationale.push_back(
        "DLL side-loading / search-order hijack: " + std::to_string(suspMod) +
        " module(s) loaded from a writable, non-system path (" + joined +
        ") (+" + std::to_string(w) + ").");
  }
  if (extNet > 0) {
    // First external endpoint is moderate; each additional one adds less,
    // capped so a noisy beacon does not dominate the score on its own.
    int w = 20 + std::min(extNet - 1, 5) * 8;
    out.score += w;
    out.rationale.push_back(
        "Outbound network egress to " + std::to_string(extNet) +
        " external endpoint(s) (non-loopback, non-RFC1918) (+" +
        std::to_string(w) + ").");
  }
  if (suspCmd > 0) {
    const int w = 15 * suspCmd;
    out.score += w;
    std::string joined;
    for (const auto &s : suspiciousCmds) {
      joined += (joined.empty() ? "" : ", ") + s;
    }
    out.rationale.push_back("Suspicious command line(s): " + joined + " (+" +
                            std::to_string(w) + ").");
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
    const int w = std::min(nonSampleCrash, 3) * 6;
    out.score += w;
    out.rationale.push_back(
        "Crash of " + std::to_string(nonSampleCrash) +
        " non-sample process(es) -- possible injection target or host "
        "instability (+" +
        std::to_string(w) + ").");
  }
  if (dataDrops > 0) {
    const int w = std::min(dataDrops, 4) * 5;
    out.score += w;
    out.rationale.push_back("Dropped " + std::to_string(dataDrops) +
                            " non-executable data file(s) (+" +
                            std::to_string(w) + ").");
  }
  if (otherMitre > 0) {
    const int w = std::min(otherMitre, 4) * 6;
    out.score += w;
    out.rationale.push_back(std::to_string(otherMitre) +
                            " additional MITRE-tagged behavior(s) observed (+" +
                            std::to_string(w) + ").");
  }

  const bool richBehavior = persistence || exeDrops || privEsc || extNet ||
                            suspCmd || suspMod || dataDrops || otherMitre;

  // ---- Map score -> verdict. ----
  // >= 60  : two strong signals, or one strong + corroboration -> Malicious
  // >= 20  : at least one noteworthy signal                    -> Suspicious
  // else   : executed cleanly                                  -> Clean
  //
  // Signed-installer FP mitigation: a present Authenticode signature is weak
  // evidence of benignity (malware is often signed with stolen/abused certs),
  // but it materially raises the Malicious bar. Without this, a legitimately
  // signed installer (drops its own EXE +30, writes a Run key +35, license/
  // update check +20 = 85) reads Malicious. Raising the bar to 90 caps that
  // common benign class at Suspicious while egregious behavior (>=90) still
  // reads Malicious even when signed.
  const int maliciousThreshold = sampleSigned ? 90 : 60;
  if (out.score >= maliciousThreshold) {
    out.verdict = Verdict::Malicious;
  } else if (out.score >= 20) {
    out.verdict = Verdict::Suspicious;
  } else {
    out.verdict = Verdict::Clean;
  }

  // Malicious requires a SAMPLE-ATTRIBUTABLE corroborating signal. Registry
  // persistence, file drops, and non-sample crashes carry no PID (poll-diff
  // telemetry) and are polluted by the sandbox's OWN boot/login/shell churn --
  // they can make a clean boot look busy but must not ALONE produce a Malicious
  // verdict (the benign-probe FP: 48 OS autostart writes + 12 shell crashes =>
  // "malicious"). The stronger, rarer signals (a dropped executable, outbound
  // egress, a suspicious command line, DLL side-loading, or other MITRE-tagged
  // behavior) are far more attributable to the sample; require at least one of
  // them to call Malicious. Without one, cap at Suspicious.
  //
  // An UNEXPECTED elevation is deliberately NOT in this set (2026-09 review):
  // it proves the process obtained higher privilege, not that it did anything
  // malicious with it, and it is trivially produced by a legitimate installer's
  // UAC prompt. It contributes weight/context, never the Malicious corroboration.
  const bool attributableMalice =
      exeDrops || extNet || suspCmd || suspMod || otherMitre;
  if (out.verdict == Verdict::Malicious && !attributableMalice) {
    out.verdict = Verdict::Suspicious;
    out.rationale.push_back(
        "Capped at Suspicious: the score is driven only by non-attributable "
        "signals (unattributed registry persistence / file drops / host-process "
        "crashes) and/or an unexpected elevation that did not require or "
        "demonstrate malicious intent; no sample-attributable malice (dropped "
        "executable, network egress, suspicious command line, DLL side-loading) "
        "corroborated it.");
  }
  if (sampleSigned && out.score >= 60 && out.verdict != Verdict::Malicious) {
    out.rationale.push_back(
        "Sample is Authenticode-signed: the Malicious threshold was raised to " +
        std::to_string(maliciousThreshold) + " (behavior scored " +
        std::to_string(out.score) +
        "), capping the verdict at Suspicious -- a present signature is not "
        "proof of benignity, but reduces confidence in a Malicious call.");
  } else if (sampleSigned && richBehavior) {
    out.rationale.push_back(
        "Sample is Authenticode-signed (factored into the verdict; a present "
        "signature is not proof of benignity).");
  }

  // ---- Evidence-sufficiency gate (2026-09 review F1). ----
  // A reassuring negative requires an observation that could have seen the
  // behavior it is denying: the run must have reached a declared end state
  // (normal completion or its time budget), the guest telemetry channel must
  // have been confirmed, and the journal must contain behavioral telemetry
  // beyond the sample launch. Anything less is recorded as an explicit
  // limitation; with no positive evidence the verdict is WITHHELD as
  // insufficient evidence instead of reported Clean. Positive behavior found
  // under partial coverage is KEPT (incomplete does not erase observed harm)
  // and the limitation lines travel with it.
  const bool declaredEnd =
      summary.completed || summary.timedOut || summary.crashed;
  const bool interrupted = summary.started && !declaredEnd;
  std::vector<std::string> coverageLimits;
  if (interrupted) {
    coverageLimits.push_back(
        "the run ended without a completion signal (interrupted, or the worker "
        "was lost before the declared end)");
  }
  if (!summary.guestAgentConnected) {
    coverageLimits.push_back(
        "the guest telemetry channel never confirmed a healthy agent, so "
        "collector coverage is unverified");
  }
  if (events.size() < 2) {
    coverageLimits.push_back(
        "the journal contains no behavioral telemetry beyond the sample "
        "launch");
  }
  if (!coverageLimits.empty()) {
    std::string joined;
    for (const auto &l : coverageLimits) {
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
    for (auto &l : coverageLimits) {
      out.limitations.push_back(std::move(l));
    }
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
    // Defensive: should not happen (rich behavior => score >= 20), but keep the
    // rationale honest if weights are retuned below threshold.
    out.rationale.push_back("Observed activity scored below the suspicious "
                            "threshold -> Clean.");
  }

  return out;
}

} // namespace antimal
