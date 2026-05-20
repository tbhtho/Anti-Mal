#include "antimal/BrowserImpact.h"
#include "antimal/Config.h"
#include "antimal/FileUtil.h"
#include "antimal/HyperVOrchestrator.h"
#include "antimal/Json.h"
#include "antimal/Report.h"
#include "antimal/Scanner.h"

#include <exception>
#include <iostream>
#include <optional>

namespace {

using antimal::Utf8ToWide;
using antimal::WideToUtf8;

std::string Arg(int argc, wchar_t **argv, int index) {
  if (index < 0 || index >= argc) {
    return {};
  }
  return WideToUtf8(argv[index]);
}

std::optional<std::string> OptionValue(int argc, wchar_t **argv, std::string_view name) {
  for (int i = 0; i + 1 < argc; ++i) {
    if (Arg(argc, argv, i) == name) {
      return Arg(argc, argv, i + 1);
    }
  }
  return std::nullopt;
}

bool HasFlag(int argc, wchar_t **argv, std::string_view name) {
  for (int i = 0; i < argc; ++i) {
    if (Arg(argc, argv, i) == name) {
      return true;
    }
  }
  return false;
}

void PrintUsage() {
  std::cout
      << "AntiMal Host CLI\n\n"
      << "Commands:\n"
      << "  antimal init\n"
      << "  antimal scan <path> [--threshold 70]\n"
      << "                    [--no-yara] [--no-capa] [--no-die] [--no-tagger]\n"
      << "                    [--intel] [--vt-key <KEY>] [--json <out.json>]\n"
      << "  antimal detonate <sample> --timeout-sec 180 --network disabled|hostonly|nat\n"
      << "  antimal base convert --vhdx <base.vhdx> --raw <AntiMalBase.raw> [--force]\n"
      << "  antimal report <run-id-or-report.json> --html\n"
      << "  antimal browser-impact <run-id-or-report.json> --decrypt-browser-secrets\n";
}

antimal::ScannerOptions BuildScannerOptions(int argc, wchar_t **argv,
                                            const antimal::AppConfig &config) {
  antimal::ScannerOptions opts;
  opts.runYara = config.enrichYara && !HasFlag(argc, argv, "--no-yara");
  opts.runCapa = config.enrichCapa && !HasFlag(argc, argv, "--no-capa");
  opts.runDie = config.enrichDie && !HasFlag(argc, argv, "--no-die");
  opts.applyTagger = config.enrichTagger && !HasFlag(argc, argv, "--no-tagger");
  opts.yaraRulesDir = config.yaraRulesDir;
  opts.tagsRulesPath = config.tagsRulesPath;
  opts.intelLookupEnabled = config.intelEnabled || HasFlag(argc, argv, "--intel");
  opts.malwareBazaarEnabled = config.intelMalwareBazaar;
  opts.virusTotalApiKey =
      OptionValue(argc, argv, "--vt-key").value_or(config.virusTotalApiKey);
  opts.intelCacheDir = config.workspaceRoot.empty()
                           ? std::filesystem::path{}
                           : config.workspaceRoot / "_intel_cache";
  return opts;
}

std::filesystem::path ResolveReportPath(const antimal::AppConfig &config,
                                        const std::filesystem::path &input) {
  if (std::filesystem::exists(input)) {
    return input;
  }
  const auto asRun = config.workspaceRoot / input / "report.json";
  if (std::filesystem::exists(asRun)) {
    return asRun;
  }
  return input;
}

int CommandInit() {
  const auto configPath = antimal::DefaultConfigPath();
  if (std::filesystem::exists(configPath)) {
    std::cout << "Config already exists: " << antimal::PathToUtf8(configPath) << "\n";
    return 0;
  }
  antimal::SaveDefaultConfig(configPath);
  std::cout << "Wrote " << antimal::PathToUtf8(configPath) << "\n";
  return 0;
}

int CommandScan(int argc, wchar_t **argv) {
  if (argc < 3) {
    PrintUsage();
    return 2;
  }
  int threshold = 70;
  if (const auto value = OptionValue(argc, argv, "--threshold")) {
    threshold = std::stoi(*value);
  }

  const auto config = antimal::LoadConfig(antimal::DefaultConfigPath());
  const auto scannerOpts = BuildScannerOptions(argc, argv, config);

  const std::filesystem::path target(argv[2]);
  auto results = antimal::ScanPath(target, scannerOpts);
  if (results.empty()) {
    std::cout << "No scan candidates found.\n";
    return 0;
  }

  int flagged = 0;
  for (const auto &result : results) {
    std::cout << antimal::FormatScanText(result);
    if (result.score >= threshold) {
      ++flagged;
      std::cout << "  sandbox: eligible\n";
    }
  }
  std::cout << "Scanned " << results.size() << " file(s), flagged " << flagged << ".\n";

  if (const auto jsonOut = OptionValue(argc, argv, "--json")) {
    std::ostringstream json;
    json << "[";
    for (size_t i = 0; i < results.size(); ++i) {
      if (i) json << ",";
      json << antimal::ToJson(results[i]);
    }
    json << "]";
    antimal::WriteTextFile(std::filesystem::path(antimal::Utf8ToWide(*jsonOut)),
                           json.str());
    std::cout << "Wrote scan JSON to " << *jsonOut << "\n";
  }
  return flagged > 0 ? 10 : 0;
}

int CommandDetonate(int argc, wchar_t **argv) {
  if (argc < 3) {
    PrintUsage();
    return 2;
  }

  auto config = antimal::LoadConfig(antimal::DefaultConfigPath());
  uint32_t timeout = config.defaultTimeoutSec;
  if (const auto value = OptionValue(argc, argv, "--timeout-sec")) {
    timeout = static_cast<uint32_t>(std::stoul(*value));
  }
  const auto networkText = OptionValue(argc, argv, "--network").value_or(antimal::ToString(config.networkMode));
  const auto network = antimal::ParseNetworkMode(networkText).value_or(antimal::NetworkMode::Disabled);

  antimal::HyperVOrchestrator orchestrator(config);
  auto progress = [](const antimal::DetonationProgress &snap) {
    if (!snap.message.empty()) {
      std::cout << "[" << snap.phase << "] " << snap.message << std::endl;
    }
  };
  const auto result = orchestrator.PrepareAndRun(
      std::filesystem::path(argv[2]), timeout, network, true, progress);

  std::cout << "Run ID: " << result.runId << "\n";
  std::cout << "Run dir: " << antimal::PathToUtf8(result.runDir) << "\n";
  std::cout << "Job: " << antimal::PathToUtf8(result.jobPath) << "\n";
  if (!result.overlayDiskPath.empty()) {
    std::cout << "Overlay disk: " << antimal::PathToUtf8(result.overlayDiskPath) << "\n";
  }
  const auto inHousePlan = result.runDir / "inhouse-plan.ps1";
  const auto genericPlan = result.runDir / "vm-plan.ps1";
  const auto vmPlan = std::filesystem::exists(inHousePlan)
                          ? inHousePlan
                          : genericPlan;
  std::cout << "VM plan: " << antimal::PathToUtf8(vmPlan) << "\n";
  for (const auto &error : result.errors) {
    std::cout << "error: " << error << "\n";
  }
  if (std::filesystem::exists(result.reportPath)) {
    const auto report = antimal::LoadReportBestEffort(result.reportPath);
    antimal::WriteReportHtml(result.runDir / "report.html", report);
    std::cout << "Report: " << antimal::PathToUtf8(result.reportPath) << "\n";
  }
  return result.errors.empty() ? 0 : 20;
}

int CommandBase(int argc, wchar_t **argv) {
  if (argc < 3 || Arg(argc, argv, 2) != "convert") {
    PrintUsage();
    return 2;
  }

  auto config = antimal::LoadConfig(antimal::DefaultConfigPath());
  const auto vhdxText = OptionValue(argc, argv, "--vhdx");
  const auto rawText = OptionValue(argc, argv, "--raw");
  const std::filesystem::path vhdx =
      vhdxText ? std::filesystem::path(Utf8ToWide(*vhdxText))
               : config.baseVhdxPath;
  const std::filesystem::path raw =
      rawText ? std::filesystem::path(Utf8ToWide(*rawText))
              : config.baseDiskPath;
  if (vhdx.empty() || raw.empty()) {
    std::cerr << "base convert needs --vhdx and --raw, or configured base paths.\n";
    return 2;
  }

  const auto result = antimal::ConvertVhdxToRaw(vhdx, raw,
                                                HasFlag(argc, argv, "--force"));
  for (const auto &message : result.messages) {
    std::cout << message << "\n";
  }
  if (!result.errors.empty()) {
    for (const auto &error : result.errors) {
      std::cerr << "error: " << error << "\n";
    }
    return 1;
  }

  config.baseVhdxPath = vhdx;
  config.baseDiskPath = raw;
  config.baseDiskFormat = "raw";
  config.vmProvider = "inhouse";
  antimal::EnsureDirectory(antimal::DefaultConfigPath().parent_path());
  antimal::WriteTextFile(antimal::DefaultConfigPath(),
                         antimal::SerializeConfig(config));

  std::cout << "VHDX: " << antimal::PathToUtf8(vhdx) << "\n";
  std::cout << "Raw:  " << antimal::PathToUtf8(raw) << "\n";
  if (result.converted) {
    std::cout << "Virtual size: " << result.virtualSize << " bytes\n";
    std::cout << "Read: " << result.bytesRead << " bytes\n";
    std::cout << "Wrote non-zero ranges: " << result.bytesWritten << " bytes\n";
  } else if (result.skipped) {
    std::cout << "Conversion skipped; raw output already exists.\n";
  }
  std::cout << "Updated config: "
            << antimal::PathToUtf8(antimal::DefaultConfigPath()) << "\n";
  return 0;
}

int CommandReport(int argc, wchar_t **argv) {
  if (argc < 3) {
    PrintUsage();
    return 2;
  }
  const auto config = antimal::LoadConfig(antimal::DefaultConfigPath());
  const auto reportPath = ResolveReportPath(config, std::filesystem::path(argv[2]));
  auto report = antimal::LoadReportBestEffort(reportPath);
  if (HasFlag(argc, argv, "--html")) {
    const auto htmlPath = reportPath.parent_path() / "report.html";
    antimal::WriteReportHtml(htmlPath, report);
    std::cout << "Wrote " << antimal::PathToUtf8(htmlPath) << "\n";
  } else {
    std::cout << antimal::ReadTextFile(reportPath) << "\n";
  }
  return 0;
}

int CommandBrowserImpact(int argc, wchar_t **argv) {
  if (argc < 3) {
    PrintUsage();
    return 2;
  }
  const auto config = antimal::LoadConfig(antimal::DefaultConfigPath());
  const auto reportPath = ResolveReportPath(config, std::filesystem::path(argv[2]));
  auto report = antimal::LoadReportBestEffort(reportPath);
  const bool decrypt = HasFlag(argc, argv, "--decrypt-browser-secrets");
  report.browserImpact = antimal::AnalyzeBrowserImpact(report.networkDomains, decrypt);

  const auto outPath = reportPath.parent_path() / "browser-impact.json";
  antimal::WriteTextFile(outPath, antimal::ToJson(report));
  antimal::WriteReportHtml(reportPath.parent_path() / "browser-impact.html", report);
  std::cout << "Wrote " << antimal::PathToUtf8(outPath) << "\n";
  std::cout << "Matched " << report.browserImpact.size() << " at-risk browser domain(s).\n";
  return 0;
}

} // namespace

int wmain(int argc, wchar_t **argv) {
  try {
    if (argc < 2) {
      PrintUsage();
      return 2;
    }
    const std::string command = Arg(argc, argv, 1);
    if (command == "init") {
      return CommandInit();
    }
    if (command == "scan") {
      return CommandScan(argc, argv);
    }
    if (command == "detonate") {
      return CommandDetonate(argc, argv);
    }
    if (command == "base") {
      return CommandBase(argc, argv);
    }
    if (command == "report") {
      return CommandReport(argc, argv);
    }
    if (command == "browser-impact") {
      return CommandBrowserImpact(argc, argv);
    }
    PrintUsage();
    return 2;
  } catch (const std::exception &ex) {
    std::cerr << "AntiMal error: " << ex.what() << "\n";
    return 1;
  }
}
