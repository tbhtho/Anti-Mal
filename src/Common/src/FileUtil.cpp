#include "antimal/FileUtil.h"

#include <Windows.h>
#include <objbase.h>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>

namespace antimal {
namespace {

std::string SystemErrorMessage(DWORD error) {
  LPWSTR buffer = nullptr;
  FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                     FORMAT_MESSAGE_IGNORE_INSERTS,
                 nullptr, error, 0, reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
  std::string result = buffer ? WideToUtf8(buffer) : "unknown Windows error";
  if (buffer) {
    LocalFree(buffer);
  }
  return Trim(result);
}

std::filesystem::path CurrentExecutableDir() {
  std::wstring buffer(MAX_PATH, L'\0');
  DWORD size = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  while (size == buffer.size()) {
    buffer.resize(buffer.size() * 2);
    size = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  }
  buffer.resize(size);
  return std::filesystem::path(buffer).parent_path();
}

} // namespace

std::wstring Utf8ToWide(std::string_view value) {
  if (value.empty()) {
    return {};
  }
  const int needed = MultiByteToWideChar(CP_UTF8, 0, value.data(),
                                         static_cast<int>(value.size()), nullptr, 0);
  if (needed <= 0) {
    throw std::runtime_error("UTF-8 to UTF-16 conversion failed");
  }
  std::wstring wide(static_cast<size_t>(needed), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                      wide.data(), needed);
  return wide;
}

std::string WideToUtf8(std::wstring_view value) {
  if (value.empty()) {
    return {};
  }
  const int needed =
      WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                          nullptr, 0, nullptr, nullptr);
  if (needed <= 0) {
    throw std::runtime_error("UTF-16 to UTF-8 conversion failed");
  }
  std::string utf8(static_cast<size_t>(needed), '\0');
  WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                      utf8.data(), needed, nullptr, nullptr);
  return utf8;
}

std::string PathToUtf8(const std::filesystem::path &path) {
  return WideToUtf8(path.wstring());
}

std::vector<uint8_t> ReadAllBytes(const std::filesystem::path &path) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    throw std::runtime_error("Unable to open file: " + PathToUtf8(path));
  }
  file.seekg(0, std::ios::end);
  const auto size = file.tellg();
  file.seekg(0, std::ios::beg);
  if (size < 0) {
    throw std::runtime_error("Unable to size file: " + PathToUtf8(path));
  }
  std::vector<uint8_t> data(static_cast<size_t>(size));
  if (!data.empty()) {
    file.read(reinterpret_cast<char *>(data.data()),
              static_cast<std::streamsize>(data.size()));
  }
  return data;
}

std::string ReadTextFile(const std::filesystem::path &path) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    throw std::runtime_error("Unable to open text file: " + PathToUtf8(path));
  }
  std::ostringstream stream;
  stream << file.rdbuf();
  return stream.str();
}

void WriteTextFile(const std::filesystem::path &path, std::string_view data) {
  EnsureDirectory(path.parent_path());
  std::ofstream file(path, std::ios::binary | std::ios::trunc);
  if (!file) {
    throw std::runtime_error("Unable to write file: " + PathToUtf8(path));
  }
  file.write(data.data(), static_cast<std::streamsize>(data.size()));
}

void WriteTextFileAtomic(const std::filesystem::path &path,
                         std::string_view data) {
  EnsureDirectory(path.parent_path());
  std::filesystem::path tmp = path;
  tmp += L".tmp";
  {
    std::ofstream file(tmp, std::ios::binary | std::ios::trunc);
    if (!file) {
      throw std::runtime_error("Unable to write temp file: " + PathToUtf8(tmp));
    }
    file.write(data.data(), static_cast<std::streamsize>(data.size()));
    file.flush();
    const bool ok = static_cast<bool>(file);
    file.close();
    if (!ok) {
      // A write/flush failure (disk full, quota) leaves a partial temp -- remove
      // it so a failed write never orphans a stale <path>.tmp on disk.
      std::error_code ec;
      std::filesystem::remove(tmp, ec);
      throw std::runtime_error("Failed writing temp file: " + PathToUtf8(tmp));
    }
  } // stream already closed above
  // MoveFileExW with MOVEFILE_REPLACE_EXISTING is an atomic same-volume replace:
  // readers see either the whole old file or the whole new one, never a partial.
  if (!MoveFileExW(tmp.wstring().c_str(), path.wstring().c_str(),
                   MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    const DWORD err = GetLastError();
    std::error_code ec;
    std::filesystem::remove(tmp, ec); // don't leave the temp behind
    throw std::runtime_error("Unable to finalize file " + PathToUtf8(path) +
                             ": " + SystemErrorMessage(err));
  }
}

void EnsureDirectory(const std::filesystem::path &path) {
  if (path.empty()) {
    return;
  }
  std::error_code ec;
  std::filesystem::create_directories(path, ec);
  if (ec) {
    throw std::runtime_error("Unable to create directory " + PathToUtf8(path) +
                             ": " + ec.message());
  }
}

std::string MakeRunId() {
  GUID guid{};
  if (CoCreateGuid(&guid) != S_OK) {
    auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    return "run-" + std::to_string(now);
  }

  wchar_t text[64]{};
  StringFromGUID2(guid, text, static_cast<int>(std::size(text)));
  std::string id = WideToUtf8(text);
  id.erase(std::remove(id.begin(), id.end(), '{'), id.end());
  id.erase(std::remove(id.begin(), id.end(), '}'), id.end());
  std::transform(id.begin(), id.end(), id.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return id;
}

std::string UtcNowIso8601() {
  const auto now = std::chrono::system_clock::now();
  const std::time_t t = std::chrono::system_clock::to_time_t(now);
  std::tm utc{};
  gmtime_s(&utc, &t);
  std::ostringstream out;
  out << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
  return out.str();
}

std::string ToLowerAscii(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

std::string Trim(std::string value) {
  auto isSpace = [](unsigned char c) { return std::isspace(c) != 0; };
  value.erase(value.begin(), std::find_if(value.begin(), value.end(),
                                          [&](char c) { return !isSpace(c); }));
  value.erase(std::find_if(value.rbegin(), value.rend(),
                           [&](char c) { return !isSpace(c); })
                  .base(),
              value.end());
  return value;
}

std::vector<std::string> Split(std::string_view text, char delimiter) {
  std::vector<std::string> parts;
  size_t start = 0;
  while (start <= text.size()) {
    const size_t pos = text.find(delimiter, start);
    if (pos == std::string_view::npos) {
      parts.emplace_back(text.substr(start));
      break;
    }
    parts.emplace_back(text.substr(start, pos - start));
    start = pos + 1;
  }
  return parts;
}

std::optional<std::filesystem::path> FindRepoRoot(std::filesystem::path start) {
  std::error_code ec;
  start = std::filesystem::absolute(start, ec);
  if (ec) {
    return std::nullopt;
  }
  for (auto current = start; !current.empty(); current = current.parent_path()) {
    if (std::filesystem::exists(current / "AntiMal.sln") ||
        std::filesystem::exists(current / "config" / "antimal.toml")) {
      return current;
    }
    if (current == current.root_path()) {
      break;
    }
  }
  return std::nullopt;
}

std::filesystem::path DefaultConfigPath() {
  if (const auto root = FindRepoRoot(CurrentExecutableDir())) {
    return *root / "config" / "antimal.toml";
  }
  if (const auto root = FindRepoRoot(std::filesystem::current_path())) {
    return *root / "config" / "antimal.toml";
  }
  return CurrentExecutableDir() / "config" / "antimal.toml";
}

} // namespace antimal
