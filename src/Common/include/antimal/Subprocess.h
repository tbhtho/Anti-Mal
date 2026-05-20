#pragma once

// Minimal subprocess runner. Wraps CreateProcessW + anonymous pipes for
// stdout/stderr capture. Used to shell out to external analysis tools
// (yara.exe, capa.exe, diec.exe) that we redistribute alongside AntiMal.
//
// Every external-tool integration in AntiMal goes through this so that
// (a) we don't sprinkle CreateProcess calls all over the codebase, and
// (b) tools can be detected-absent and skipped cleanly without crashing
//     anything. See src/Common/include/antimal/Yara.h for the canonical
//     consumer pattern.

#include <chrono>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace antimal {

struct SubprocessResult {
  bool launched = false;        // CreateProcessW succeeded.
  bool timedOut = false;        // Process was killed by the timeout.
  int exitCode = -1;            // Process exit code (0 on success).
  std::string stdoutText;       // Captured stdout (utf-8).
  std::string stderrText;       // Captured stderr (utf-8).
  std::string failureReason;    // Set when launched == false.
};

struct SubprocessOptions {
  std::filesystem::path workingDirectory;   // Empty = inherit.
  std::chrono::milliseconds timeout{0};     // 0 = no timeout.
  bool combineStderrIntoStdout = false;     // Useful for tools that mix them.
  bool inheritEnvironment = true;
};

// Runs `executable` with the given argv, returns captured output. Never
// throws: failures populate the result struct. `executable` may be a bare
// name (resolved via PATH) or an absolute path.
SubprocessResult RunSubprocess(const std::filesystem::path &executable,
                               const std::vector<std::string> &args,
                               const SubprocessOptions &options = {});

// Returns the absolute path of `name` resolved against either:
//   1. The directory containing the current executable (so we can ship
//      `yara.exe` etc. next to AntiMal.exe).
//   2. A `tools\` subdirectory next to the current executable.
//   3. The system PATH.
// Empty optional means the binary is not available on this machine.
std::optional<std::filesystem::path> ResolveToolPath(std::string_view name);

} // namespace antimal
