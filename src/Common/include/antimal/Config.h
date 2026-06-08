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
