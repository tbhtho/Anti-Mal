#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace antimal {

std::wstring Utf8ToWide(std::string_view value);
std::string WideToUtf8(std::wstring_view value);
std::string PathToUtf8(const std::filesystem::path &path);
std::vector<uint8_t> ReadAllBytes(const std::filesystem::path &path);
std::string ReadTextFile(const std::filesystem::path &path);
void WriteTextFile(const std::filesystem::path &path, std::string_view data);
// Like WriteTextFile, but crash-safe: writes to "<path>.tmp" then atomically
// replaces the destination. A dirty-kill mid-write can never leave a truncated,
// unparseable file at `path` -- the old file survives intact until the rename.
void WriteTextFileAtomic(const std::filesystem::path &path, std::string_view data);
void EnsureDirectory(const std::filesystem::path &path);
std::string MakeRunId();
std::string UtcNowIso8601();
std::string ToLowerAscii(std::string value);
std::string Trim(std::string value);
std::vector<std::string> Split(std::string_view text, char delimiter);
std::optional<std::filesystem::path> FindRepoRoot(std::filesystem::path start);
std::filesystem::path DefaultConfigPath();

} // namespace antimal
