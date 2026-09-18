#pragma once

// Assistant - the integrated host-side analysis assistant.
//
// Responsibility split (deliberate, security-relevant):
//
//   human request -> structured plan -> trusted authorization/policy checks
//     -> typed AntiMal tools -> shared live session -> evidence store
//     -> grounded explanation
//
// The MODEL proposes actions. Application code (AssistantToolRunner) validates
// every proposal against AssistantPolicy and the bound run, then executes it
// through the same LiveVm primitives the GUI/CLI/MCP use. The model is neither
// the security boundary nor the source of run state.
//
// Untrusted guest content (screenshots, dialogs, logs, filenames, network data)
// is EVIDENCE, never instructions: the tools below are the entire action
// surface. There is deliberately no host shell / host filesystem / arbitrary
// process tool, so a prompt injection inside a guest window cannot reach the
// host through this interface.
//
// The module is provider-neutral. `FakeAssistantProvider` is the deterministic
// test facility (it can deliberately request forbidden tools so enforcement is
// tested); `CreateOpenAiCompatibleProvider` is the real HTTP adapter.

#include "antimal/Config.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace antimal {

// ---- Provider-neutral conversation types ------------------------------------

struct AssistantMessage {
  // "system" | "user" | "assistant" | "tool"
  std::string role;
  std::string content;
  // Set on "tool" messages: the id of the AssistantToolCall being answered.
  std::string toolCallId;
  // Assistant messages that requested tools (echoed back to providers that
  // require the full assistant turn in the transcript).
  struct ToolCall {
    std::string id;
    std::string name;
    std::string argumentsJson;
  };
  std::vector<ToolCall> toolCalls;
};

struct AssistantToolCall {
  std::string id;
  std::string name;
  std::string argumentsJson; // opaque JSON object from the model
};

struct AssistantUsage {
  int promptTokens = 0;
  int completionTokens = 0;
};

struct ProviderCapabilities {
  bool tools = false;
  bool vision = false;
  bool streaming = false;
};

struct AssistantCompletion {
  bool ok = false;
  std::string content;
  std::vector<AssistantToolCall> toolCalls;
  std::string error; // transport/parse/provider failure when ok == false
  // True when the failure is retryable (timeout, 429, 5xx). The loop backs off
  // and retries a bounded number of times; paid requests are never retried
  // unboundedly.
  bool retryable = false;
  AssistantUsage usage;
};

// Cancellation is cooperative and checked between steps (and inside the HTTP
// call for the real provider).
using AssistantCancelFn = std::function<bool()>;

class AssistantProvider {
public:
  virtual ~AssistantProvider() = default;
  virtual std::string Name() const = 0;
  virtual ProviderCapabilities Capabilities() const = 0;
  virtual AssistantCompletion Complete(
      const std::vector<AssistantMessage> &messages,
      const std::string &toolsJson, // OpenAI-style tools array; "[]" = none
      const AssistantCancelFn &cancel) = 0;
};

// ---- Policy ------------------------------------------------------------------

// The OPERATOR'S approved investigation plan. The model can never construct or
// modify this: it is supplied by the human-facing surface (CLI/GUI) and the
// runner refuses any session action that is not backed by it. This is how the
// assistant can start an approved investigation without ever gaining raw
// hypervisor or arbitrary-process power.
struct AssistantSessionPlan {
  std::filesystem::path packagePath;
  // Expected SHA-256 of the package bytes. Verified (streaming) before the
  // session is created, so a file swapped after approval is refused.
  std::string packageSha256;
  // Optional entrypoint for folder/media packages ("" = the package file).
  std::string entrypoint;
  NetworkMode networkMode = NetworkMode::Disabled;
  // Launch the approved entrypoint inside the guest. Only ever set by the
  // operator's plan; the model cannot enable it.
  bool allowExecution = false;
  // 0 = interactive until stopped (no hidden wall-clock analysis budget).
  uint32_t timeoutSec = 0;
  bool showViewer = true;
};

// Validates a plan without touching a VM: package exists, declared hash (when
// given) matches the actual bytes, timeout within the supported range, network
// mode supported. Pure enough to unit-test; used by the runner before any
// session tool is delegated and re-checked by the live bridge.
bool ValidateAssistantSessionPlan(const AssistantSessionPlan &plan,
                                  std::string *error);

// Everything the model is permitted to do. Defaults are observation-only: the
// policy is what turns "the model asked" into "the product allowed".
struct AssistantPolicy {
  // Guest input (clicks/typing). Visible to the operator in the live view; the
  // default allows it because operating the guest IS the requested workflow.
  bool allowGuestInput = true;
  // Ending the live session requires explicit authority (the operator asked for
  // a bounded investigation, or granted it at plan time).
  bool allowFinalize = false;
  // Creating/booting a session and attaching the viewer. Requires BOTH this
  // flag and an approved AssistantSessionPlan; neither is model-settable.
  bool allowSessionControl = false;
  // Launching the approved sample. Only ever set from the approved plan, never
  // from a model request.
  bool allowSampleExecution = false;
  int maxTurns = 24;          // model round-trips
  int maxToolCalls = 40;      // total executed actions
};

enum class ToolCallOutcome {
  Ok,
  Denied,   // policy refused the action (enforced outside the model)
  Failed,   // the tool ran and failed
  Cancelled,
  Unknown,  // outcome could not be established (must be reconciled, not retried)
};

struct AssistantToolResult {
  ToolCallOutcome outcome = ToolCallOutcome::Failed;
  std::string resultJson;  // model-visible result
  std::string evidenceRef; // human-visible evidence (artifact path / event line)
};

// ---- Live-session bridge -----------------------------------------------------

// Typed operations over the running session. Implemented by LiveVmBridge
// (LiveVm-backed, production) and FakeVmBridge (deterministic tests).
// Every method returns a JSON object with at least {"ok":bool} and, on
// failure, {"error":"..."}; that contract is what the runner enforces.
class AssistantVmBridge {
public:
  virtual ~AssistantVmBridge() = default;
  virtual std::string Status() = 0;
  virtual std::string Screenshot(const std::string &outPath) = 0;
  virtual std::string Click(int x, int y, const std::string &button,
                            int clicks) = 0;
  virtual std::string Move(int x, int y) = 0;
  virtual std::string Drag(int x1, int y1, int x2, int y2,
                           const std::string &button) = 0;
  virtual std::string Type(const std::string &text) = 0;
  virtual std::string Key(const std::string &key) = 0;
  virtual std::string Chord(const std::string &chord) = 0;
  virtual std::string Events(const std::string &run, long long sinceLine,
                             int limit, const std::string &filter) = 0;
  virtual std::string Processes(const std::string &run) = 0;
  virtual std::string Report(const std::string &run) = 0;
  virtual std::string Finalize(bool wait) = 0;
  // Create + boot a session from the OPERATOR-APPROVED plan. The bridge
  // re-validates the plan (including the package hash) before spawning the
  // worker; it never accepts a path from the model.
  virtual std::string BootSession(const AssistantSessionPlan &plan) = 0;
  // Open the watchable viewer window for the live session.
  virtual std::string AttachViewer() = 0;
};

// ---- Tool runner --------------------------------------------------------------

// Validates then executes one proposed call. Enforces:
//   * the tool name is in the fixed allow-list (unknown -> Denied),
//   * policy flags (finalize / execution / input),
//   * the bound run id still matches the live session (stale clients cannot
//     act on a different run; the bridge's Status is only consulted for
//     observation calls when no run is bound),
//   * a total tool-call budget.
class AssistantToolRunner {
public:
  AssistantToolRunner(AssistantVmBridge *bridge, AssistantPolicy policy);
  // The operator's approved plan (nullptr = no lifecycle authority at all).
  // The runner never takes a plan from the model.
  void SetSessionPlan(std::shared_ptr<const AssistantSessionPlan> plan) {
    plan_ = std::move(plan);
  }
  std::shared_ptr<const AssistantSessionPlan> SessionPlan() const {
    return plan_;
  }
  // True when a session may be created/booted (policy AND a valid plan).
  bool SessionControlAvailable() const;

  AssistantToolResult Run(const AssistantToolCall &call,
                          const std::string &boundRunId = std::string());

  int ToolCallCount() const { return toolCalls_; }
  const std::vector<std::string> &ActionLog() const { return actionLog_; }
  const std::vector<std::string> &EvidenceRefs() const { return evidenceRefs_; }
  void SetPolicy(const AssistantPolicy &policy) { policy_ = policy; }

private:
  AssistantVmBridge *bridge_ = nullptr;
  AssistantPolicy policy_;
  std::shared_ptr<const AssistantSessionPlan> plan_;
  int toolCalls_ = 0;
  std::vector<std::string> actionLog_;
  std::vector<std::string> evidenceRefs_;
};

// The fixed tool schema (OpenAI function-tool array). Shared by the real
// provider requests, the fake-provider tests, and the docs, so the declared
// surface and the enforced surface cannot drift.
const char *AssistantToolsJson();

// The default operator system prompt (evidence-first, untrusted-guest rule,
// bounded-action discipline).
std::string DefaultAssistantSystemPrompt();

// ---- Agent loop ----------------------------------------------------------------

struct AssistantEvent {
  std::string type; // "text" | "tool" | "denied" | "error" | "final"
  std::string text; // human-readable line
};

struct AssistantRunOptions {
  std::string task;
  std::string boundRunId; // session this run may act on ("" = newest)
  AssistantCancelFn cancel;
  std::function<void(const AssistantEvent &)> onEvent;
  int maxTurns = 0;     // 0 = policy default
  int maxToolCalls = 0; // 0 = policy default
  // Bounded provider failure handling: at most this many retries for one
  // completion, and this many consecutive failures before giving up. Paid
  // requests are never retried unboundedly.
  int maxProviderRetries = 2;
  int maxConsecutiveProviderErrors = 3;
};

struct AssistantRunResult {
  bool ok = false;
  bool cancelled = false;
  bool budgetExhausted = false;
  std::string summary; // final model text (or an honest stop reason)
  std::string error;
  int turns = 0;
  int toolCalls = 0;
  int deniedCalls = 0;
  int providerErrors = 0;
  AssistantUsage usage;
  std::vector<std::string> actions;
  std::vector<std::string> evidence;
};

AssistantRunResult RunAssistant(AssistantProvider &provider,
                                AssistantToolRunner &runner,
                                const AssistantRunOptions &options);

// ---- Providers ------------------------------------------------------------------

// Deterministic scripted provider for tests and contract development. Each
// call pops the next scripted completion; requests are recorded verbatim for
// assertions. Calling `ScriptForbiddenToolCall` is how enforcement tests make
// the model ask for something it must not get.
class FakeAssistantProvider final : public AssistantProvider {
public:
  explicit FakeAssistantProvider(
      std::vector<AssistantCompletion> script = {});

  std::string Name() const override { return "fake"; }
  ProviderCapabilities Capabilities() const override {
    ProviderCapabilities c;
    c.tools = true;
    return c;
  }
  AssistantCompletion Complete(const std::vector<AssistantMessage> &messages,
                               const std::string &toolsJson,
                               const AssistantCancelFn &cancel) override;

  void Push(AssistantCompletion completion) {
    script_.push_back(std::move(completion));
  }
  // Convenience: a plain assistant text turn.
  void PushText(const std::string &text);
  // Convenience: an assistant turn that requests one tool.
  void PushToolCall(const std::string &id, const std::string &name,
                    const std::string &argsJson);
  // A transport failure (retryable=false unless `retryable`).
  void PushError(const std::string &error, bool retryable = false);

  const std::vector<std::vector<AssistantMessage>> &Requests() const {
    return requests_;
  }
  const std::string &LastToolsJson() const { return lastToolsJson_; }

private:
  std::vector<AssistantCompletion> script_;
  size_t cursor_ = 0;
  std::vector<std::vector<AssistantMessage>> requests_;
  std::string lastToolsJson_;
};

// Production bridge over the running live session. Actions go through the same
// LiveVm primitives the GUI/CLI/MCP use (framebuffer section + `_live-input.bin`
// framing + the closed-loop pointer), so an assistant action is visible in the
// operator's live view and validated identically. Screenshots land under
// <workspace_root>/_assistant/.
std::unique_ptr<AssistantVmBridge> CreateLiveVmAssistantBridge(
    const AppConfig &config);

// Real provider: OpenAI-compatible /v1/chat/completions (OpenAI, Azure OpenAI
// gateways, and local OpenAI-compatible servers such as llama.cpp/Ollama's
// compatibility endpoint). The API key is supplied by the caller from host-side
// secret storage (environment) -- never from the repository, guest, UI script,
// or evidence. Returns nullptr with `error` set on invalid configuration.
std::unique_ptr<AssistantProvider> CreateOpenAiCompatibleProvider(
    const AppConfig &config, const std::string &baseUrl,
    const std::string &apiKey, const std::string &model,
    std::string *error);

} // namespace antimal
