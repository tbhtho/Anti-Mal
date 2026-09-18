#include "antimal/AgentCli.h"

#include "antimal/FileUtil.h"
#include "antimal/JsonValue.h"
#include "antimal/Subprocess.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstring>

namespace antimal {
namespace {

const char *KindName(AgentCliKind kind) {
  switch (kind) {
  case AgentCliKind::OpenCode: return "opencode";
  case AgentCliKind::CommandCode: return "command-code";
  case AgentCliKind::Kimi: return "kimi";
  case AgentCliKind::Antigravity: return "antigravity";
  }
  return "agent";
}

std::string TrimWs(const std::string &v) {
  size_t b = 0, e = v.size();
  while (b < e && (std::isspace(static_cast<unsigned char>(v[b])) != 0)) ++b;
  while (e > b && (std::isspace(static_cast<unsigned char>(v[e - 1])) != 0)) --e;
  return v.substr(b, e - b);
}

std::string StripPrefix(const std::string &id) {
  const auto colon = id.find(':');
  return colon == std::string::npos ? id : id.substr(colon + 1);
}

// Model ids look like "provider/model" with a conservative charset (mirrors the
// Bloxmesh regex) so headers/metadata lines are not mistaken for models.
bool LooksLikeModelId(const std::string &line) {
  const auto slash = line.find('/');
  if (slash == std::string::npos || slash == 0 || slash + 1 >= line.size()) {
    return false;
  }
  for (char c : line) {
    const bool ok = std::isalnum(static_cast<unsigned char>(c)) != 0 ||
                    c == '/' || c == '.' || c == '_' || c == '-' || c == ':';
    if (!ok) {
      return false;
    }
  }
  return line.find(' ') == std::string::npos;
}

std::vector<std::string> SplitLines(const std::string &text) {
  std::vector<std::string> lines;
  std::string current;
  for (char c : text) {
    if (c == '\n') {
      lines.push_back(current);
      current.clear();
    } else if (c != '\r') {
      current.push_back(c);
    }
  }
  if (!current.empty()) {
    lines.push_back(current);
  }
  return lines;
}

bool FileExists(const std::filesystem::path &p) {
  std::error_code ec;
  return !p.empty() && std::filesystem::is_regular_file(p, ec);
}

std::filesystem::path SearchExe(const std::string &exeName,
                                const std::vector<std::filesystem::path> &extraDirs) {
  for (const auto &dir : extraDirs) {
    const auto candidate = dir / (exeName + ".exe");
    if (FileExists(candidate)) {
      return candidate;
    }
    const auto cmd = dir / (exeName + ".cmd");
    if (FileExists(cmd)) {
      return cmd;
    }
  }
  wchar_t buffer[MAX_PATH]{};
  const std::wstring wide = Utf8ToWide(exeName) + L".exe";
  const DWORD found = SearchPathW(nullptr, wide.c_str(), nullptr, MAX_PATH, buffer,
                                  nullptr);
  if (found > 0 && found < MAX_PATH) {
    return std::filesystem::path(buffer);
  }
  return {};
}

} // namespace

AgentCli ResolveAgentCli(AgentCliKind kind,
                         const std::vector<std::filesystem::path> &extraDirs) {
  AgentCli cli;
  cli.kind = kind;
  cli.name = KindName(kind);
  std::vector<std::filesystem::path> dirs = extraDirs;
  if (const char *appData = std::getenv("APPDATA")) {
    dirs.emplace_back(std::filesystem::path(appData) / "npm");
  }
  if (const char *profile = std::getenv("USERPROFILE")) {
    const std::filesystem::path home(profile);
    dirs.emplace_back(home / ".opencode" / "bin");
    dirs.emplace_back(home / ".kimi-code" / "bin"); // kimi ships here, not npm
    dirs.emplace_back(home / ".antigravity" / "bin");
  }
  cli.command = SearchExe(cli.name, dirs);
  cli.available = !cli.command.empty();
  if (!cli.available) {
    cli.error = cli.name + " CLI not found on PATH or in the npm global bin";
  }
  return cli;
}

std::vector<AgentModel> ParseOpenCodeModels(const std::string &output) {
  std::vector<AgentModel> models;
  const auto lines = SplitLines(output);
  for (size_t i = 0; i < lines.size(); ++i) {
    const std::string line = TrimWs(lines[i]);
    if (!LooksLikeModelId(line)) {
      continue;
    }
    AgentModel model;
    model.id = std::string("opencode:") + line;
    model.displayName = line;
    // Optional metadata on the following lines (name / default flag).
    for (size_t j = i + 1; j < lines.size() && j <= i + 4; ++j) {
      const std::string meta = TrimWs(lines[j]);
      if (LooksLikeModelId(meta)) {
        break;
      }
      if (meta.find("\"default\": true") != std::string::npos ||
          meta.find("\"default\":true") != std::string::npos) {
        model.isDefault = true;
      }
      const auto nameKey = meta.find("\"name\"");
      if (nameKey != std::string::npos) {
        const auto first = meta.find('"', meta.find(':', nameKey) + 1);
        const auto last = first == std::string::npos
                              ? std::string::npos
                              : meta.find('"', first + 1);
        if (last != std::string::npos && last > first + 1) {
          model.displayName = meta.substr(first + 1, last - first - 1);
        }
      }
    }
    models.push_back(std::move(model));
  }
  return models;
}

std::vector<AgentModel> ParseCommandCodeModels(const std::string &output) {
  std::vector<AgentModel> models;
  for (const std::string &rawLine : SplitLines(output)) {
    std::string line = TrimWs(rawLine);
    if (line.empty()) {
      continue;
    }
    const bool isDefault = line.find("(default)") != std::string::npos;
    // The id is the first whitespace-delimited token that looks like one.
    std::string id;
    std::string rest;
    const auto space = line.find_first_of(" \t");
    if (space == std::string::npos) {
      id = line;
    } else {
      id = line.substr(0, space);
      rest = TrimWs(line.substr(space + 1));
    }
    if (!LooksLikeModelId(id)) {
      continue;
    }
    AgentModel model;
    model.id = std::string("command-code:") + id;
    model.displayName = rest.empty() ? id : (id + " - " + rest);
    model.isDefault = isDefault;
    models.push_back(std::move(model));
  }
  return models;
}

std::vector<AgentModel> ParseKimiModels(const std::string &output) {
  std::vector<AgentModel> models;
  const auto parsed = ParseJson(output);
  if (!parsed.has_value() || !parsed->IsObject()) {
    return models; // older builds: nothing to offer rather than a wrong picker
  }
  const JsonValue &list = parsed->At("models");
  if (!list.IsObject()) {
    return models;
  }
  for (const auto &[alias, info] : list.object) {
    AgentModel model;
    model.id = std::string("kimi:") + alias;
    std::string pretty;
    if (info.IsObject() && info.At("name").IsString()) {
      pretty = info.At("name").AsString();
    }
    model.displayName = pretty.empty() ? alias : (pretty + " - " + alias);
    models.push_back(std::move(model));
  }
  return models;
}

std::vector<AgentModel> ParseAntigravityModels(const std::string &output) {
  std::vector<AgentModel> models;
  const auto parsed = ParseJson(output);
  if (parsed.has_value() && parsed->IsArray()) {
    for (const auto &entry : parsed->array) {
      const std::string id = entry.IsString()
                                 ? entry.AsString()
                                 : (entry.IsObject() ? entry.At("id").AsString()
                                                     : std::string());
      if (id.empty()) {
        continue;
      }
      AgentModel model;
      model.id = std::string("antigravity:") + id;
      model.displayName = id;
      models.push_back(std::move(model));
    }
    return models;
  }
  // Line-oriented fallback.
  for (const std::string &rawLine : SplitLines(output)) {
    const std::string line = TrimWs(rawLine);
    if (line.empty() || line.find(' ') != std::string::npos) {
      continue;
    }
    AgentModel model;
    model.id = std::string("antigravity:") + line;
    model.displayName = line;
    models.push_back(std::move(model));
  }
  return models;
}

std::vector<std::string> BuildModelListArgs(AgentCliKind kind) {
  switch (kind) {
  case AgentCliKind::OpenCode:
    return {"models", "--verbose"};
  case AgentCliKind::CommandCode:
    return {"--list-models"};
  case AgentCliKind::Kimi:
    return {"provider", "list", "--json"};
  case AgentCliKind::Antigravity:
    return {"--list-models"};
  }
  return {};
}

std::vector<std::string> BuildRunArgs(AgentCliKind kind, const std::string &model,
                                      const std::string &sessionId,
                                      const std::string &prompt) {
  const std::string plainModel = StripPrefix(model);
  std::vector<std::string> args;
  switch (kind) {
  case AgentCliKind::OpenCode:
    args = {"run", "--model", plainModel};
    if (!sessionId.empty()) {
      args.push_back("--session");
      args.push_back(sessionId);
    }
    args.push_back(prompt);
    break;
  case AgentCliKind::CommandCode:
    args = {"--model", plainModel, "--output-format", "stream-json", "--prompt",
            prompt};
    break;
  case AgentCliKind::Kimi:
    args = {"-p", prompt, "--output-format", "stream-json", "--model", plainModel};
    break;
  case AgentCliKind::Antigravity:
    args = {"--input-format", "stream-json", "--output-format", "stream-json",
            "--model", plainModel, "--prompt", prompt};
    break;
  }
  return args;
}

AgentRunResult RunAgentCli(const AgentCli &cli, const std::vector<std::string> &args,
                           const std::filesystem::path &workingDir,
                           const std::function<void(const std::string &)> &onChunk,
                           const std::function<bool()> &cancel) {
  AgentRunResult result;
  if (!cli.available) {
    result.error = cli.error.empty() ? "agent CLI is not available" : cli.error;
    return result;
  }
  // A .cmd/.bat shim (npm installs) cannot be CreateProcess'd directly: route
  // it through cmd.exe, exactly like Bloxmesh routes its JS entries via node.
  std::filesystem::path launchCommand = cli.command;
  const std::string extension = cli.command.extension().string();
  const bool needsShell = extension == ".cmd" || extension == ".bat";
  if (needsShell) {
    wchar_t comspec[MAX_PATH]{};
    const DWORD n = GetEnvironmentVariableW(L"ComSpec", comspec, MAX_PATH);
    launchCommand = (n > 0 && n < MAX_PATH) ? std::filesystem::path(comspec)
                                            : std::filesystem::path(L"cmd.exe");
  }

  // Quote every argument the way CreateProcessW expects.
  std::wstring commandLine;
  auto append = [&commandLine](const std::wstring &token) {
    if (!commandLine.empty()) {
      commandLine.push_back(L' ');
    }
    commandLine.push_back(L'"');
    for (wchar_t c : token) {
      if (c == L'"') {
        commandLine.push_back(L'\\');
      }
      commandLine.push_back(c);
    }
    commandLine.push_back(L'"');
  };
  append(launchCommand.wstring());
  if (needsShell) {
    append(L"/c");
    append(cli.command.wstring());
  }
  for (const auto &a : args) {
    append(Utf8ToWide(a));
  }

  SECURITY_ATTRIBUTES sa{};
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;
  HANDLE readPipe = nullptr, writePipe = nullptr;
  if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) {
    result.error = "CreatePipe failed";
    return result;
  }
  SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

  STARTUPINFOW si{};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdOutput = writePipe;
  si.hStdError = writePipe;
  si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  PROCESS_INFORMATION pi{};
  std::wstring mutableCmd = commandLine;
  const BOOL ok = CreateProcessW(
      launchCommand.wstring().c_str(), mutableCmd.data(), nullptr, nullptr, TRUE,
      CREATE_NO_WINDOW, nullptr,
      workingDir.empty() ? nullptr : workingDir.c_str(), &si, &pi);
  CloseHandle(writePipe);
  if (!ok) {
    CloseHandle(readPipe);
    result.error = "could not start " + cli.name;
    return result;
  }
  result.started = true;

  // A job object guarantees the whole agent tree dies on cancel.
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  if (job != nullptr) {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION info{};
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info,
                            sizeof(info));
    AssignProcessToJobObject(job, pi.hProcess);
  }

  char buffer[4096];
  for (;;) {
    if (cancel && cancel()) {
      result.cancelled = true;
      if (job != nullptr) {
        TerminateJobObject(job, 1);
      } else {
        TerminateProcess(pi.hProcess, 1);
      }
      break;
    }
    DWORD available = 0;
    if (!PeekNamedPipe(readPipe, nullptr, 0, nullptr, &available, nullptr)) {
      break; // agent closed its output
    }
    if (available == 0) {
      if (WaitForSingleObject(pi.hProcess, 60) == WAIT_OBJECT_0) {
        break;
      }
      continue;
    }
    DWORD got = 0;
    const DWORD want = (std::min)(available, static_cast<DWORD>(sizeof(buffer)));
    if (!ReadFile(readPipe, buffer, want, &got, nullptr) || got == 0) {
      break;
    }
    result.output.append(buffer, got);
    if (onChunk) {
      onChunk(std::string(buffer, got));
    }
  }
  WaitForSingleObject(pi.hProcess, 15000);
  DWORD exitCode = 1;
  GetExitCodeProcess(pi.hProcess, &exitCode);
  result.exitCode = static_cast<int>(exitCode);
  CloseHandle(readPipe);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  if (job != nullptr) {
    CloseHandle(job);
  }
  return result;
}

} // namespace antimal
