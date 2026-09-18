// AssistantCmd.cpp - `antimal assistant "<task>"`: the integrated AI operator.
//
// Runs one investigation task against the live session using the shared
// Assistant core: a provider-neutral model client, the typed AntiMal VM tools,
// and trusted policy enforcement OUTSIDE the model. Writes an auditable
// transcript (task, policy, actions, evidence refs, usage) next to the run so
// a human can review exactly what the assistant was allowed to do and did.

#include "antimal/Assistant.h"
#include "antimal/Config.h"
#include "antimal/Crypto.h"
#include "antimal/FileUtil.h"
#include "antimal/Json.h"
#include "antimal/JsonValue.h"
#include "antimal/LiveVm.h"

#include <windows.h>

#include <iostream>
#include <string>
#include <vector>

namespace {

// --- Test-fixture provider (--provider fake) ---------------------------------
// A DETERMINISTIC scripted "model" used to demonstrate and test the evidence
// loop without an API key. It is loudly labeled everywhere it appears and is
// never the default. On its final turn it parses the tool results it received
// and cites the actual counts, so the transcript proves the evidence path --
// it does not invent observations.
class FixtureAssistantProvider final : public antimal::AssistantProvider {
public:
  // "evidence": status -> events -> processes -> report -> summarize.
  // "live":     status -> screenshot -> click -> screenshot -> summarize
  //             (drives a real live session when one is running).
  explicit FixtureAssistantProvider(std::string script)
      : script_(std::move(script)) {}

  std::string Name() const override { return "fixture-scripted (NOT a model)"; }
  antimal::ProviderCapabilities Capabilities() const override {
    antimal::ProviderCapabilities c;
    c.tools = true;
    return c;
  }
  antimal::AssistantCompletion Complete(
      const std::vector<antimal::AssistantMessage> &messages,
      const std::string &, const antimal::AssistantCancelFn &cancel) override {
    using namespace antimal;
    if (cancel && cancel()) {
      AssistantCompletion c;
      c.error = "cancelled";
      return c;
    }
    const int toolResults =
        static_cast<int>(std::count_if(messages.begin(), messages.end(),
                                       [](const AssistantMessage &m) {
                                         return m.role == "tool";
                                       }));
    AssistantCompletion c;
    c.ok = true;
    if (script_ == "boot") {
      // status -> vm_boot (approved plan) -> status -> summarize
      if (toolResults == 0) {
        c.toolCalls.push_back({"b1", "vm_status", "{}"});
        return c;
      }
      if (toolResults == 1) {
        c.toolCalls.push_back({"b2", "vm_boot", "{}"});
        return c;
      }
      if (toolResults == 2) {
        c.toolCalls.push_back({"b3", "vm_status", "{}"});
        return c;
      }
      std::string bootNote = "(no boot result)";
      for (const auto &m : messages) {
        if (m.role != "tool") {
          continue;
        }
        const auto parsed = ParseJson(m.content);
        if (parsed.has_value() && parsed->Has("pid")) {
          bootNote = "boot started pid=" +
                     std::to_string(parsed->At("pid").AsInt64()) +
                     " seeded=" +
                     (parsed->At("seeded").AsBool() ? "true" : "false") +
                     " timeoutSec=" +
                     std::to_string(parsed->At("timeoutSec").AsInt64());
        }
      }
      c.content = "[fixture summary] " + bootNote +
                  ". The session is up; reaching the guest desktop takes "
                  "minutes. This fixture does not claim readiness it did not "
                  "observe.";
      return c;
    }
    if (script_ == "live") {
      if (toolResults == 0) {
        c.toolCalls.push_back({"l1", "vm_status", "{}"});
        return c;
      }
      if (toolResults == 1) {
        c.toolCalls.push_back({"l2", "vm_screenshot", "{}"});
        return c;
      }
      if (toolResults == 2) {
        c.toolCalls.push_back({"l3", "vm_click", R"({"x":640,"y":400})"});
        return c;
      }
      if (toolResults == 3) {
        c.toolCalls.push_back({"l4", "vm_screenshot", "{}"});
        return c;
      }
      // Summarize the ACTUAL click result and the two screenshot paths.
      std::string clickResult = "(no click result)";
      std::string shots;
      for (const auto &m : messages) {
        if (m.role != "tool") {
          continue;
        }
        const auto parsed = ParseJson(m.content);
        if (!parsed.has_value()) {
          continue;
        }
        if (parsed->Has("finalError")) {
          clickResult = "click ok=" +
                        std::string(parsed->At("ok").AsBool() ? "true" : "false") +
                        ", residual error (" +
                        std::to_string(parsed->At("finalError").At("x").AsInt64()) +
                        "," +
                        std::to_string(parsed->At("finalError").At("y").AsInt64()) +
                        ") px";
        }
        const JsonValue &p = parsed->At("path");
        if (p.IsString()) {
          shots += (shots.empty() ? "" : ", ") + p.AsString();
        }
      }
      c.content =
          "[fixture summary] Live session observed; " + clickResult +
          "; screenshots: " + (shots.empty() ? "(none)" : shots) +
          ". Verification requires reading the before/after screenshots -- this "
          "fixture does not claim an effect it did not see.";
      return c;
    }
    if (toolResults == 0) {
      c.toolCalls.push_back({"f1", "vm_status", "{}"});
      return c;
    }
    if (toolResults == 1) {
      c.toolCalls.push_back({"f2", "vm_events", R"({"limit":25})"});
      return c;
    }
    if (toolResults == 2) {
      c.toolCalls.push_back({"f3", "vm_processes", "{}"});
      return c;
    }
    if (toolResults == 3) {
      c.toolCalls.push_back({"f4", "vm_report", "{}"});
      return c;
    }
    // Summarize ONLY from the tool results actually received.
    int eventLines = 0;
    int processes = 0;
    std::string verdict = "(no finalized report)";
    for (const auto &m : messages) {
      if (m.role != "tool") {
        continue;
      }
      const auto parsed = ParseJson(m.content);
      if (!parsed.has_value()) {
        continue;
      }
      eventLines += static_cast<int>(parsed->At("lines").array.size());
      processes += static_cast<int>(parsed->At("processes").array.size());
      const JsonValue &v = parsed->At("verdict");
      if (v.IsString()) {
        verdict = v.AsString();
      }
    }
    c.content =
        "[fixture summary] Evidence read: " + std::to_string(eventLines) +
        " journal line(s), " + std::to_string(processes) +
        " observed process(es), report verdict: " + verdict +
        ". This text was produced by a deterministic test fixture, not a model; "
        "it exists to prove the evidence path (tools -> transcript) works "
        "end-to-end.";
    return c;
  }

private:
  std::string script_; // "evidence" | "live"
};

std::string Narrow(const std::wstring &w) {
  if (w.empty()) {
    return {};
  }
  const int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0,
                                    nullptr, nullptr);
  std::string s(n > 0 ? n - 1 : 0, '\0');
  if (n > 1) {
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), n, nullptr,
                        nullptr);
  }
  return s;
}

bool HasFlag(int argc, wchar_t **argv, const wchar_t *name) {
  for (int i = 2; i < argc; ++i) {
    if (std::wcscmp(argv[i], name) == 0) {
      return true;
    }
  }
  return false;
}

std::wstring OptValue(int argc, wchar_t **argv, const wchar_t *name) {
  for (int i = 2; i + 1 < argc; ++i) {
    if (std::wcscmp(argv[i], name) == 0) {
      return argv[i + 1];
    }
  }
  return std::wstring();
}

std::string EnvValue(const char *name) {
  char buf[4096]{};
  size_t needed = 0;
  if (getenv_s(&needed, buf, sizeof(buf), name) != 0 || needed <= 1) {
    return {};
  }
  return std::string(buf);
}

std::string Stamp() {
  SYSTEMTIME st{};
  GetLocalTime(&st);
  char buf[64];
  std::snprintf(buf, sizeof(buf), "%04d%02d%02d-%02d%02d%02d", st.wYear,
                st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
  return buf;
}

} // namespace

int CommandAssistant(int argc, wchar_t **argv) {
  using namespace antimal;

  if (HasFlag(argc, argv, L"--help") || HasFlag(argc, argv, L"-h") ||
      argc < 3) {
    std::cout
        << "usage: antimal assistant \"<task>\" [options]\n"
        << "  --run <id>            bind to a specific run (default: newest)\n"
        << "  --model <name>        override assistant_model\n"
        << "  --base-url <url>      override assistant_base_url\n"
        << "  --max-actions <N>     tool-call budget (default 40)\n"
        << "  --max-turns <N>       model round-trip budget (default 24)\n"
        << "  --allow-finalize      permit ending the live session (vm_finalize)\n"
        << "  --no-guest-input      refuse clicks/typing (observation only)\n"
        << "  --cancel-file <path>  cooperative pause: create this file to stop\n"
        << "                        the assistant before its next action\n"
        << "  --provider fake [--fake-script evidence|live]\n"
        << "                        deterministic TEST FIXTURE (no network)\n"
        << "\nApproved session control (operator-only; the model cannot set it):\n"
        << "  --allow-session-control      permit vm_boot / vm_attach_viewer\n"
        << "  --plan-package <path>        the approved package file\n"
        << "  --plan-sha256 <hash>         optional; computed from the file if absent\n"
        << "  --plan-execute               authorize launching the entrypoint\n"
        << "  --plan-network disabled|hostonly|nat\n"
        << "  --plan-timeout-sec <N>       0 = until stopped (default)\n"
        << "\nThe API key is read from ANTIMAL_ASSISTANT_API_KEY (or\n"
        << "OPENAI_API_KEY). It is never read from the repository or the guest.\n";
    return argc < 3 ? 2 : 0;
  }

  std::string task;
  for (int i = 2; i < argc; ++i) {
    const std::wstring a = argv[i];
    if (a.rfind(L"--", 0) == 0) {
      // Skip the flag's value when it takes one.
      if (a == L"--run" || a == L"--model" || a == L"--base-url" ||
          a == L"--max-actions" || a == L"--max-turns" ||
          a == L"--cancel-file" || a == L"--provider" || a == L"--fake-script" ||
          a == L"--plan-package" || a == L"--plan-sha256" ||
          a == L"--plan-network" || a == L"--plan-timeout-sec") {
        ++i;
      }
      continue;
    }
    task = Narrow(a);
    break;
  }
  if (task.empty()) {
    std::cerr << "assistant: a task string is required\n";
    return 2;
  }

  AppConfig config = LoadConfig(DefaultConfigPath());
  const std::string run = Narrow(OptValue(argc, argv, L"--run"));
  std::string model = Narrow(OptValue(argc, argv, L"--model"));
  if (model.empty()) {
    model = config.assistantModel;
  }
  std::string baseUrl = Narrow(OptValue(argc, argv, L"--base-url"));
  if (baseUrl.empty()) {
    baseUrl = config.assistantBaseUrl;
  }
  std::string apiKey = EnvValue("ANTIMAL_ASSISTANT_API_KEY");
  if (apiKey.empty()) {
    apiKey = EnvValue("OPENAI_API_KEY");
  }

  std::string providerError;
  std::unique_ptr<AssistantProvider> provider;
  const bool fixtureProvider = HasFlag(argc, argv, L"--provider") &&
                               Narrow(OptValue(argc, argv, L"--provider")) ==
                                   "fake";
  if (fixtureProvider) {
    std::string script = Narrow(OptValue(argc, argv, L"--fake-script"));
    provider = std::make_unique<FixtureAssistantProvider>(
        script.empty() ? "evidence" : script);
  } else {
    provider = CreateOpenAiCompatibleProvider(config, baseUrl, apiKey, model,
                                              &providerError);
  }
  if (!provider) {
    if (HasFlag(argc, argv, L"--json")) {
      std::cout << "{\"ok\":false,\"error\":" << JsonQuote(providerError)
                << "}\n";
    } else {
      std::cerr << "assistant: " << providerError << "\n";
    }
    return 3;
  }

  AssistantPolicy policy;
  policy.allowGuestInput = !HasFlag(argc, argv, L"--no-guest-input");
  policy.allowFinalize =
      HasFlag(argc, argv, L"--allow-finalize") || config.assistantAllowFinalize;
  policy.allowSessionControl = HasFlag(argc, argv, L"--allow-session-control");
  policy.maxToolCalls = 40;
  policy.maxTurns = 24;
  if (const std::wstring v = OptValue(argc, argv, L"--max-actions");
      !v.empty()) {
    const int n = _wtoi(v.c_str());
    if (n > 0 && n <= 500) {
      policy.maxToolCalls = n;
    }
  }
  if (const std::wstring v = OptValue(argc, argv, L"--max-turns"); !v.empty()) {
    const int n = _wtoi(v.c_str());
    if (n > 0 && n <= 200) {
      policy.maxTurns = n;
    }
  }

  std::unique_ptr<AssistantVmBridge> bridge = CreateLiveVmAssistantBridge(config);
  AssistantToolRunner runner(bridge.get(), policy);

  // The OPERATOR's approved plan. Supplied only from this CLI surface; the
  // model can neither see nor modify it, and vm_boot is refused without it.
  std::shared_ptr<const AssistantSessionPlan> plan;
  std::string planSummary = "(none)";
  if (const std::wstring pkg = OptValue(argc, argv, L"--plan-package");
      !pkg.empty()) {
    auto p = std::make_shared<AssistantSessionPlan>();
    p->packagePath = pkg;
    p->packageSha256 = Narrow(OptValue(argc, argv, L"--plan-sha256"));
    if (p->packageSha256.empty()) {
      try {
        p->packageSha256 = Sha256File(p->packagePath); // bind to bytes
      } catch (const std::exception &ex) {
        std::cerr << "assistant: cannot hash the planned package: " << ex.what()
                  << "\n";
        return 2;
      }
    }
    p->allowExecution = HasFlag(argc, argv, L"--plan-execute");
    if (const std::wstring net = OptValue(argc, argv, L"--plan-network");
        !net.empty()) {
      const auto mode = ParseNetworkMode(Narrow(net));
      if (!mode.has_value()) {
        std::cerr << "assistant: --plan-network must be "
                     "disabled|hostonly|nat\n";
        return 2;
      }
      p->networkMode = *mode;
    }
    if (const std::wstring to = OptValue(argc, argv, L"--plan-timeout-sec");
        !to.empty()) {
      const int n = _wtoi(to.c_str());
      if (n < 0) {
        std::cerr << "assistant: --plan-timeout-sec must be >= 0\n";
        return 2;
      }
      p->timeoutSec = static_cast<uint32_t>(n);
    }
    std::string planError;
    if (!ValidateAssistantSessionPlan(*p, &planError)) {
      std::cerr << "assistant: approved plan is invalid: " << planError << "\n";
      return 2;
    }
    plan = p;
    planSummary = PathToUtf8(p->packagePath) + " sha256=" +
                  p->packageSha256.substr(0, 16) + "... exec=" +
                  (p->allowExecution ? "yes" : "no") + " net=" +
                  ToString(p->networkMode) + " timeout=" +
                  (p->timeoutSec == 0 ? std::string("until-stopped")
                                      : std::to_string(p->timeoutSec) + "s");
    runner.SetSessionPlan(plan);
  }
  if (policy.allowSessionControl && !plan) {
    std::cerr << "assistant: --allow-session-control requires --plan-package "
                 "(the model must never choose the package)\n";
    return 2;
  }

  // Cooperative pause: creating this file stops the loop before its next
  // action, exactly like the GUI's Pause AI (the VM is untouched).
  AssistantCancelFn cancelFn;
  const std::string cancelPath = Narrow(OptValue(argc, argv, L"--cancel-file"));
  if (!cancelPath.empty()) {
    const std::string cancelPathLocal = cancelPath;
    cancelFn = [cancelPathLocal]() {
      std::error_code ec;
      return std::filesystem::exists(std::filesystem::path(cancelPathLocal), ec);
    };
  }

  const ProviderCapabilities caps = provider->Capabilities();
  if (!HasFlag(argc, argv, L"--json")) {
    if (fixtureProvider) {
      std::cout << "*** TEST FIXTURE PROVIDER: deterministic script, not a "
                   "model; no data leaves this machine. ***\n";
    }
    std::cout << "assistant provider : " << provider->Name() << "\n"
              << "model              : " << model << "\n"
              << "endpoint           : " << baseUrl << "\n"
              << "capabilities       : tools=" << (caps.tools ? "yes" : "no")
              << " vision=" << (caps.vision ? "yes" : "no") << "\n"
              << "policy             : guest-input="
              << (policy.allowGuestInput ? "yes" : "no")
              << " finalize=" << (policy.allowFinalize ? "yes" : "no")
              << " max-actions=" << policy.maxToolCalls
              << " max-turns=" << policy.maxTurns << "\n"
              << "session control    : "
              << (policy.allowSessionControl ? "approved" : "denied")
              << " plan=" << planSummary << "\n"
              << "data sharing       : " << config.assistantSharing
              << " (text/metadata only; binary uploads are never performed)\n"
              << "run binding        : " << (run.empty() ? "(newest)" : run)
              << "\n\ntask: " << task << "\n\n";
  }

  AssistantRunOptions options;
  options.task = task;
  options.boundRunId = run;
  options.maxToolCalls = policy.maxToolCalls;
  options.maxTurns = policy.maxTurns;
  options.cancel = cancelFn;
  options.onEvent = [&](const AssistantEvent &event) {
    if (HasFlag(argc, argv, L"--json")) {
      return;
    }
    if (event.type == "text") {
      std::cout << "\n[assistant] " << event.text << "\n";
    } else {
      std::cout << "[" << event.type << "] " << event.text << std::endl;
    }
  };

  // The operator asking the assistant to act hands actuator ownership to it
  // (shared, cross-process lease). A human takeover mid-task revokes it, and
  // the tool guards then deny any queued action at delivery time.
  antimal::LiveInputLease inputLease(config.workspaceRoot /
                                     antimal::kInputLeaseFileName);
  inputLease.TakeOver("assistant");
  const AssistantRunResult result = RunAssistant(*provider, runner, options);
  inputLease.Release("assistant");

  // Auditable transcript: what was asked, under which policy, what ran, what
  // was cited, what it cost. Written next to the run (or the workspace).
  {
    const LiveRun newest = FindNewestRun(config.workspaceRoot);
    std::filesystem::path dir = run.empty()
                                    ? newest.dir
                                    : config.workspaceRoot / Utf8ToWide(run);
    if (dir.empty()) {
      dir = config.workspaceRoot;
    }
    const std::filesystem::path transcript =
        dir / ("assistant-" + Stamp() + ".json");
    std::string j = "{\n  \"task\": " + JsonQuote(task) + ",\n";
    j += "  \"provider\": " + JsonQuote(provider->Name()) + ",\n";
    j += "  \"model\": " + JsonQuote(model) + ",\n";
    j += "  \"boundRun\": " + JsonQuote(run) + ",\n";
    j += std::string("  \"policy\": {\"guestInput\": ") +
         (policy.allowGuestInput ? "true" : "false") +
         ", \"finalize\": " + (policy.allowFinalize ? "true" : "false") +
         ", \"maxToolCalls\": " + std::to_string(policy.maxToolCalls) +
         ", \"maxTurns\": " + std::to_string(policy.maxTurns) + "},\n";
    j += std::string("  \"result\": {\"ok\": ") +
         (result.ok ? "true" : "false") +
         ", \"cancelled\": " + (result.cancelled ? "true" : "false") +
         ", \"budgetExhausted\": " +
         (result.budgetExhausted ? "true" : "false") +
         ", \"turns\": " + std::to_string(result.turns) +
         ", \"toolCalls\": " + std::to_string(result.toolCalls) +
         ", \"deniedCalls\": " + std::to_string(result.deniedCalls) +
         ", \"providerErrors\": " + std::to_string(result.providerErrors) +
         ", \"promptTokens\": " + std::to_string(result.usage.promptTokens) +
         ", \"completionTokens\": " +
         std::to_string(result.usage.completionTokens) + "},\n";
    j += "  \"summary\": " + JsonQuote(result.summary) + ",\n";
    if (!result.error.empty()) {
      j += "  \"error\": " + JsonQuote(result.error) + ",\n";
    }
    j += "  \"actions\": [";
    for (size_t i = 0; i < result.actions.size(); ++i) {
      j += (i ? ", " : "") + JsonQuote(result.actions[i]);
    }
    j += "],\n  \"evidence\": [";
    for (size_t i = 0; i < result.evidence.size(); ++i) {
      j += (i ? ", " : "") + JsonQuote(result.evidence[i]);
    }
    j += "]\n}\n";
    try {
      EnsureDirectory(dir);
      WriteTextFileAtomic(transcript, j);
      if (!HasFlag(argc, argv, L"--json")) {
        std::cout << "\ntranscript: " << PathToUtf8(transcript) << "\n";
      }
    } catch (const std::exception &ex) {
      std::cerr << "assistant: could not write transcript: " << ex.what()
                << "\n";
    }
  }

  if (HasFlag(argc, argv, L"--json")) {
    std::string j = "{\"ok\":";
    j += result.ok ? "true" : "false";
    j += ",\"cancelled\":";
    j += result.cancelled ? "true" : "false";
    j += ",\"budgetExhausted\":";
    j += result.budgetExhausted ? "true" : "false";
    j += ",\"turns\":" + std::to_string(result.turns);
    j += ",\"toolCalls\":" + std::to_string(result.toolCalls);
    j += ",\"deniedCalls\":" + std::to_string(result.deniedCalls);
    j += ",\"providerErrors\":" + std::to_string(result.providerErrors);
    j += ",\"promptTokens\":" + std::to_string(result.usage.promptTokens);
    j += ",\"completionTokens\":" +
         std::to_string(result.usage.completionTokens);
    j += ",\"summary\":" + JsonQuote(result.summary);
    j += ",\"error\":" + JsonQuote(result.error);
    j += ",\"actions\":[";
    for (size_t i = 0; i < result.actions.size(); ++i) {
      j += (i ? "," : "") + JsonQuote(result.actions[i]);
    }
    j += "]}\n";
    std::cout << j;
  } else {
    std::cout << "\n" << (result.ok ? "done" : "stopped") << ": "
              << result.summary << "\n";
    if (!result.error.empty()) {
      std::cout << "error: " << result.error << "\n";
    }
    std::cout << "turns " << result.turns << ", actions " << result.toolCalls
              << ", denied " << result.deniedCalls << ", provider errors "
              << result.providerErrors << ", tokens "
              << result.usage.promptTokens << "+"
              << result.usage.completionTokens << "\n";
  }
  return result.ok ? 0 : 4;
}
