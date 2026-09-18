#pragma once

// AgentCli - provider adapters that drive installed CLI agents (the pattern
// mirrored from Bloxmesh-Plus's src/main/workbench/*-provider.ts).
//
// AntiMal never holds model credentials: each adapter resolves an installed CLI,
// asks it for its model list, and runs it with a prompt, streaming its output.
// The agent's tool set is the AntiMal MCP server (`antimal` in opencode.json),
// so a chat turn can drive the live VM through the same typed tools the GUI/CLI
// use. Session ids are preserved per agent so follow-up turns continue the same
// conversation.
//
// Deliberately split the same way Bloxmesh does:
//   resolve / list  (discovery, cheap, cached by the caller)
//   build args      (pure, unit-testable per agent)
//   stream          (spawn + read stdout/stderr, cancellable)
//   stop            (kill the process tree)

#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace antimal {

enum class AgentCliKind {
  OpenCode,     // opencode        models --verbose
  CommandCode,  // command-code    --list-models
  Kimi,         // kimi            provider list --json
  Antigravity,  // antigravity     (stream-json in/out)
};

struct AgentModel {
  std::string id;          // passed to BuildRunArgs (e.g. "opencode:build/x")
  std::string displayName; // shown in the picker
  bool isDefault = false;
};

// One resolved CLI. `command` is the executable; `prefixArgs` covers CLIs that
// must be launched through a wrapper (e.g. a node entry point).
struct AgentCli {
  AgentCliKind kind = AgentCliKind::OpenCode;
  std::string name;                      // "opencode" | "command-code" | ...
  std::filesystem::path command;
  std::vector<std::string> prefixArgs;
  bool available = false;
  std::string error; // why unavailable, for the UI
};

// Discovery. `extraDirs` is searched in addition to PATH (the app passes the
// npm global bin and %USERPROFILE%\.opencode\bin, like Bloxmesh does).
AgentCli ResolveAgentCli(AgentCliKind kind,
                         const std::vector<std::filesystem::path> &extraDirs = {});

// --- pure parsing of each CLI's model listing (unit-tested) ------------------
std::vector<AgentModel> ParseOpenCodeModels(const std::string &output);
std::vector<AgentModel> ParseCommandCodeModels(const std::string &output);
std::vector<AgentModel> ParseKimiModels(const std::string &output);
std::vector<AgentModel> ParseAntigravityModels(const std::string &output);

// --- pure argv builders (unit-tested) ----------------------------------------
std::vector<std::string> BuildModelListArgs(AgentCliKind kind);
// `model` may carry the picker prefix ("opencode:build/x"); it is stripped here.
// `sessionId` ("ses_...") is honoured only by agents that support continuity.
std::vector<std::string> BuildRunArgs(AgentCliKind kind, const std::string &model,
                                      const std::string &sessionId,
                                      const std::string &prompt);

// --- streaming run -----------------------------------------------------------
struct AgentRunResult {
  bool started = false;
  int exitCode = -1;
  bool cancelled = false;
  std::string output; // full transcript (stdout+stderr interleaved as read)
  std::string error;
};

// Runs the agent to completion, invoking `onChunk` as output arrives (the chat
// panel appends it live). `cancel` is polled between reads; on cancel the whole
// process tree is terminated. Blocking; callers run it on a worker thread.
AgentRunResult RunAgentCli(const AgentCli &cli, const std::vector<std::string> &args,
                           const std::filesystem::path &workingDir,
                           const std::function<void(const std::string &)> &onChunk,
                           const std::function<bool()> &cancel);

} // namespace antimal
