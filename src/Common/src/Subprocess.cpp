#include "antimal/Subprocess.h"

#include "antimal/FileUtil.h"

#include <Windows.h>

#include <array>
#include <thread>

namespace antimal {
namespace {

struct HandleCloser {
  void operator()(HANDLE h) const noexcept {
    if (h && h != INVALID_HANDLE_VALUE) {
      CloseHandle(h);
    }
  }
};

struct PipeEnds {
  HANDLE readEnd = nullptr;
  HANDLE writeEnd = nullptr;
};

bool CreateInheritablePipe(PipeEnds &pipe, bool readInheritable, bool writeInheritable) {
  SECURITY_ATTRIBUTES sa{};
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;
  if (!CreatePipe(&pipe.readEnd, &pipe.writeEnd, &sa, 0)) {
    return false;
  }
  // Pipes default to both ends inheritable; clear inheritance on the side
  // we keep so the child can't accidentally inherit it.
  if (!readInheritable) {
    SetHandleInformation(pipe.readEnd, HANDLE_FLAG_INHERIT, 0);
  }
  if (!writeInheritable) {
    SetHandleInformation(pipe.writeEnd, HANDLE_FLAG_INHERIT, 0);
  }
  return true;
}

// Drains a pipe into `out` until EOF. Runs on a worker thread so the parent
// doesn't block when the child fills both stdout and stderr buffers at once.
void DrainPipe(HANDLE readEnd, std::string &out) {
  std::array<char, 4096> buffer{};
  DWORD read = 0;
  while (ReadFile(readEnd, buffer.data(), static_cast<DWORD>(buffer.size()),
                  &read, nullptr) &&
         read > 0) {
    out.append(buffer.data(), read);
  }
}

// Quotes `arg` per the Win32 CommandLineToArgvW round-trip rules. Needed
// because CreateProcessW takes a single command-line string, not argv[].
std::wstring QuoteArg(const std::wstring &arg) {
  if (!arg.empty() && arg.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
    return arg;
  }
  std::wstring out;
  out.push_back(L'"');
  for (size_t i = 0; i < arg.size();) {
    size_t backslashes = 0;
    while (i < arg.size() && arg[i] == L'\\') {
      ++i;
      ++backslashes;
    }
    if (i == arg.size()) {
      out.append(backslashes * 2, L'\\');
      break;
    }
    if (arg[i] == L'"') {
      out.append(backslashes * 2 + 1, L'\\');
      out.push_back(L'"');
    } else {
      out.append(backslashes, L'\\');
      out.push_back(arg[i]);
    }
    ++i;
  }
  out.push_back(L'"');
  return out;
}

std::wstring BuildCommandLine(const std::filesystem::path &executable,
                              const std::vector<std::string> &args) {
  std::wstring cmd = QuoteArg(executable.wstring());
  for (const auto &arg : args) {
    cmd.push_back(L' ');
    cmd.append(QuoteArg(Utf8ToWide(arg)));
  }
  return cmd;
}

} // namespace

SubprocessResult RunSubprocess(const std::filesystem::path &executable,
                               const std::vector<std::string> &args,
                               const SubprocessOptions &options) {
  SubprocessResult result;

  PipeEnds outPipe;
  PipeEnds errPipe;
  if (!CreateInheritablePipe(outPipe, false, true)) {
    result.failureReason = "CreatePipe(stdout) failed";
    return result;
  }
  if (!options.combineStderrIntoStdout) {
    if (!CreateInheritablePipe(errPipe, false, true)) {
      CloseHandle(outPipe.readEnd);
      CloseHandle(outPipe.writeEnd);
      result.failureReason = "CreatePipe(stderr) failed";
      return result;
    }
  }

  STARTUPINFOW si{};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdOutput = outPipe.writeEnd;
  si.hStdError = options.combineStderrIntoStdout ? outPipe.writeEnd
                                                 : errPipe.writeEnd;
  si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

  std::wstring cmd = BuildCommandLine(executable, args);
  // CreateProcessW may modify the buffer in-place; give it a writable copy.
  std::wstring cmdMutable = cmd;
  cmdMutable.push_back(L'\0');

  std::wstring workingDir = options.workingDirectory.wstring();
  const wchar_t *workingDirPtr = workingDir.empty() ? nullptr : workingDir.c_str();

  PROCESS_INFORMATION pi{};
  const BOOL ok = CreateProcessW(nullptr, cmdMutable.data(), nullptr, nullptr,
                                 TRUE, CREATE_NO_WINDOW,
                                 options.inheritEnvironment ? nullptr : nullptr,
                                 workingDirPtr, &si, &pi);

  // Close the child-side handles in the parent regardless of CreateProcess
  // outcome — the child has its own copy when launched.
  CloseHandle(outPipe.writeEnd);
  outPipe.writeEnd = nullptr;
  if (!options.combineStderrIntoStdout) {
    CloseHandle(errPipe.writeEnd);
    errPipe.writeEnd = nullptr;
  }

  if (!ok) {
    const DWORD err = GetLastError();
    CloseHandle(outPipe.readEnd);
    if (!options.combineStderrIntoStdout) {
      CloseHandle(errPipe.readEnd);
    }
    char buf[128];
    _snprintf_s(buf, _TRUNCATE, "CreateProcessW failed (GLE=%lu)",
                static_cast<unsigned long>(err));
    result.failureReason = buf;
    return result;
  }

  result.launched = true;

  // Drain pipes on worker threads to avoid deadlocking on full pipe buffers.
  std::thread outDrainer([&] { DrainPipe(outPipe.readEnd, result.stdoutText); });
  std::thread errDrainer;
  if (!options.combineStderrIntoStdout) {
    errDrainer = std::thread([&] { DrainPipe(errPipe.readEnd, result.stderrText); });
  }

  DWORD waitTimeout = INFINITE;
  if (options.timeout.count() > 0) {
    waitTimeout = static_cast<DWORD>(
        options.timeout.count() > 0 ? options.timeout.count() : 0);
  }
  const DWORD waitResult = WaitForSingleObject(pi.hProcess, waitTimeout);
  if (waitResult == WAIT_TIMEOUT) {
    result.timedOut = true;
    TerminateProcess(pi.hProcess, 1);
    WaitForSingleObject(pi.hProcess, INFINITE);
  }

  DWORD exitCode = 1;
  GetExitCodeProcess(pi.hProcess, &exitCode);
  result.exitCode = static_cast<int>(exitCode);

  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);

  // Drainers exit when the child closes the write side of the pipes (which
  // happens automatically when the child process dies).
  outDrainer.join();
  if (errDrainer.joinable()) {
    errDrainer.join();
  }

  CloseHandle(outPipe.readEnd);
  if (!options.combineStderrIntoStdout) {
    CloseHandle(errPipe.readEnd);
  }

  return result;
}

std::optional<std::filesystem::path> ResolveToolPath(std::string_view name) {
  // 1. Same directory as the current executable.
  wchar_t modulePath[MAX_PATH]{};
  if (GetModuleFileNameW(nullptr, modulePath, MAX_PATH) == 0) {
    return std::nullopt;
  }
  const auto exeDir = std::filesystem::path(modulePath).parent_path();
  const auto nameWide = Utf8ToWide(name);

  const std::filesystem::path candidate1 = exeDir / nameWide;
  if (std::filesystem::exists(candidate1)) {
    return candidate1;
  }
  const std::filesystem::path candidate2 = exeDir / L"tools" / nameWide;
  if (std::filesystem::exists(candidate2)) {
    return candidate2;
  }

  // 2. PATH search via SearchPathW.
  wchar_t resolved[MAX_PATH]{};
  const DWORD got = SearchPathW(nullptr, nameWide.c_str(), nullptr, MAX_PATH,
                                resolved, nullptr);
  if (got > 0 && got < MAX_PATH) {
    return std::filesystem::path(resolved);
  }

  return std::nullopt;
}

} // namespace antimal
