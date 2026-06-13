#pragma once

#include "antimal/Types.h"

#include <filesystem>
#include <optional>
#include <string>

namespace antimal {

struct AppConfig {
  std::filesystem::path baseVhdxPath;
  std::filesystem::path baseDiskPath = "C:\\AntiMalRuns\\_base\\AntiMalBase.raw";
  std::string baseDiskFormat = "raw";
  std::filesystem::path workspaceRoot = "C:\\AntiMalRuns";
  std::string vmNamePrefix = "AntiMal";
  uint32_t defaultTimeoutSec = 180;
  NetworkMode networkMode = NetworkMode::Disabled;
  std::string driverBridgeMode = "off";
  std::string vmProvider = "inhouse";

  // Enrichment / dynamic-observation knobs. All default to a safe,
  // offline-only posture; enabling network or external tools is explicit.
  bool enrichYara = true;
  bool enrichCapa = true;
  bool enrichDie = true;
  bool enrichTagger = true;
  bool intelEnabled = false;          // master switch for network lookups
  bool intelMalwareBazaar = true;     // free, no key — only relevant when intel_enabled
  std::string virusTotalApiKey;       // empty → VT skipped
  std::filesystem::path yaraRulesDir; // empty → default lookup near exe
  std::filesystem::path tagsRulesPath;
  uint32_t screenshotIntervalMs = 2000;
  bool collectScreenshots = true;
  bool dynamicExecutionEnabled = false;

  // Workspace retention. 0 = unlimited (keep every run's artifacts forever — the
  // historical behavior). When > 0, the orchestrator prunes the OLDEST run
  // directories at start-of-run so at most N most-recent non-live runs survive.
  // The per-run ~3 GB disposable overlay is reclaimed end-of-run regardless.
  int workspaceRetentionRuns = 0;

  // Virtual guest-clock base, as a unix epoch (seconds). 0 = auto (the VM
  // captures host time once at boot so TLS/cert validation works, then advances
  // it on its own crystal — never re-reading host wall-clock). A non-zero value
  // pins the guest's start date, e.g. to trigger date-gated "logic bomb"
  // malware. The live control path is the ANTIMAL_GUEST_EPOCH env var, which the
  // orchestrator sets per run; this field is the persisted source for it.
  int64_t vmGuestClockEpoch = 0;

  // Live-VM ("Boot VM (live)") hands-free login. The seed snapshot lands on the
  // Win11 lock/login screen; this controls how the desktop is reached:
  //   "password"  — auto-type vmLoginPassword (proven to reach the desktop)
  //   "autologon" — patch the disposable overlay for AutoAdminLogon (no password
  //                 typed at all; the user-requested "no password" mode)
  //   "manual"    — type nothing; the analyst logs in via the live console
  std::string vmLoginMode = "password";
  std::string vmLoginPassword = "AntiMal!23";
};

AppConfig LoadConfig(const std::filesystem::path &path);
void SaveDefaultConfig(const std::filesystem::path &path);
std::string SerializeConfig(const AppConfig &config);

} // namespace antimal
