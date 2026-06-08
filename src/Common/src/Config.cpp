#include "antimal/Config.h"

#include "antimal/FileUtil.h"

#include <sstream>
#include <stdexcept>

namespace antimal {
namespace {

std::string StripQuotes(std::string value) {
  value = Trim(value);
  if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
    value = value.substr(1, value.size() - 2);
  }
  return value;
}

bool ParseBool(const std::string &value) {
  auto lower = ToLowerAscii(Trim(value));
  return lower == "true" || lower == "yes" || lower == "on" || lower == "1";
}

void ApplyConfigValue(AppConfig &config, std::string key, std::string value) {
  key = Trim(key);
  value = StripQuotes(value);

  if (key == "base_vhdx_path") {
    config.baseVhdxPath = Utf8ToWide(value);
  } else if (key == "base_disk_path") {
    config.baseDiskPath = Utf8ToWide(value);
  } else if (key == "base_disk_format") {
    config.baseDiskFormat = ToLowerAscii(value);
  } else if (key == "workspace_root") {
    config.workspaceRoot = Utf8ToWide(value);
  } else if (key == "vm_name_prefix") {
    config.vmNamePrefix = value;
  } else if (key == "default_timeout_sec") {
    config.defaultTimeoutSec = static_cast<uint32_t>(std::stoul(value));
  } else if (key == "network_mode") {
    auto parsed = ParseNetworkMode(value);
    if (!parsed) {
      throw std::runtime_error("Invalid network_mode: " + value);
    }
    config.networkMode = *parsed;
  } else if (key == "driver_bridge_mode") {
    config.driverBridgeMode = value;
  } else if (key == "vm_provider") {
    config.vmProvider = value;
  } else if (key == "enrich_yara") {
    config.enrichYara = ParseBool(value);
  } else if (key == "enrich_capa") {
    config.enrichCapa = ParseBool(value);
  } else if (key == "enrich_die") {
    config.enrichDie = ParseBool(value);
  } else if (key == "enrich_tagger") {
    config.enrichTagger = ParseBool(value);
  } else if (key == "intel_enabled") {
    config.intelEnabled = ParseBool(value);
  } else if (key == "intel_malwarebazaar") {
    config.intelMalwareBazaar = ParseBool(value);
  } else if (key == "virustotal_api_key") {
    config.virusTotalApiKey = value;
  } else if (key == "yara_rules_dir") {
    config.yaraRulesDir = Utf8ToWide(value);
  } else if (key == "tags_rules_path") {
    config.tagsRulesPath = Utf8ToWide(value);
  } else if (key == "screenshot_interval_ms") {
    config.screenshotIntervalMs = static_cast<uint32_t>(std::stoul(value));
  } else if (key == "collect_screenshots") {
    config.collectScreenshots = ParseBool(value);
  } else if (key == "dynamic_execution_enabled") {
    config.dynamicExecutionEnabled = ParseBool(value);
  } else if (key == "vm_login_mode") {
    config.vmLoginMode = value;
  } else if (key == "vm_login_password") {
    config.vmLoginPassword = value;
  }
}

} // namespace

AppConfig LoadConfig(const std::filesystem::path &path) {
  AppConfig config;
  if (!std::filesystem::exists(path)) {
    return config;
  }

  std::string content = ReadTextFile(path);
  // Strip a leading UTF-8 BOM (EF BB BF) if present. Windows PowerShell 5.1's
  // `Set-Content -Encoding UTF8` (used by the project's own Write-AntiMalConfig)
  // prepends one; without stripping it the first key (base_vhdx_path) carries the
  // BOM, never matches, and the base path is silently left empty -> the in-house
  // orchestrator then reports "no readable base VHDX is available".
  if (content.size() >= 3 && static_cast<unsigned char>(content[0]) == 0xEF &&
      static_cast<unsigned char>(content[1]) == 0xBB &&
      static_cast<unsigned char>(content[2]) == 0xBF) {
    content.erase(0, 3);
  }
  std::istringstream input(content);
  std::string line;
  while (std::getline(input, line)) {
    const auto comment = line.find('#');
    if (comment != std::string::npos) {
      line.erase(comment);
    }
    line = Trim(line);
    if (line.empty()) {
      continue;
    }
    const auto equals = line.find('=');
    if (equals == std::string::npos) {
      continue;
    }
    ApplyConfigValue(config, line.substr(0, equals), line.substr(equals + 1));
  }
  return config;
}

std::string SerializeConfig(const AppConfig &config) {
  auto boolStr = [](bool b) { return b ? "true" : "false"; };
  std::ostringstream out;
  out << "base_vhdx_path = \"" << PathToUtf8(config.baseVhdxPath) << "\"\n";
  out << "base_disk_path = \"" << PathToUtf8(config.baseDiskPath) << "\"\n";
  out << "base_disk_format = \"" << config.baseDiskFormat << "\"\n";
  out << "workspace_root = \"" << PathToUtf8(config.workspaceRoot) << "\"\n";
  out << "vm_name_prefix = \"" << config.vmNamePrefix << "\"\n";
  out << "default_timeout_sec = " << config.defaultTimeoutSec << "\n";
  out << "network_mode = \"" << ToString(config.networkMode) << "\"\n";
  out << "driver_bridge_mode = \"" << config.driverBridgeMode << "\"\n";
  out << "vm_provider = \"" << config.vmProvider << "\"\n";
  out << "\n# Enrichment pipeline. Tools shell out to redistributables next to AntiMal.exe.\n";
  out << "enrich_yara = " << boolStr(config.enrichYara) << "\n";
  out << "enrich_capa = " << boolStr(config.enrichCapa) << "\n";
  out << "enrich_die = " << boolStr(config.enrichDie) << "\n";
  out << "enrich_tagger = " << boolStr(config.enrichTagger) << "\n";
  out << "yara_rules_dir = \"" << PathToUtf8(config.yaraRulesDir) << "\"\n";
  out << "tags_rules_path = \"" << PathToUtf8(config.tagsRulesPath) << "\"\n";
  out << "\n# Network-required threat intel. Off by default. virustotal needs a key.\n";
  out << "intel_enabled = " << boolStr(config.intelEnabled) << "\n";
  out << "intel_malwarebazaar = " << boolStr(config.intelMalwareBazaar) << "\n";
  out << "virustotal_api_key = \"" << config.virusTotalApiKey << "\"\n";
  out << "\n# Dynamic-observation knobs. Read by GuestAgent.\n";
  out << "dynamic_execution_enabled = " << boolStr(config.dynamicExecutionEnabled) << "\n";
  out << "collect_screenshots = " << boolStr(config.collectScreenshots) << "\n";
  out << "screenshot_interval_ms = " << config.screenshotIntervalMs << "\n";
  out << "\n# Live-VM hands-free login: password | autologon (no password) | manual.\n";
  out << "vm_login_mode = \"" << config.vmLoginMode << "\"\n";
  out << "vm_login_password = \"" << config.vmLoginPassword << "\"\n";
  return out.str();
}

void SaveDefaultConfig(const std::filesystem::path &path) {
  AppConfig config;
  WriteTextFile(path, SerializeConfig(config));
}

} // namespace antimal
