#include "antimal/FileSystemTelemetry.h"

#include "antimal/FileUtil.h"  // UtcNowIso8601, PathToUtf8

#include <Windows.h>

namespace antimal {

namespace {

EventRecord MakeFileEvent(const std::string &path, const FileMeta &meta,
                          std::string action) {
  EventRecord ev;
  ev.timestampUtc = UtcNowIso8601();
  ev.source = "GuestAgent";
  ev.category = "file";
  ev.action = std::move(action);
  ev.target = path;
  ev.details["size"] = std::to_string(meta.size);
  return ev;
}

std::filesystem::path EnvDir(const wchar_t *name) {
  wchar_t buffer[1024];
  const DWORD len = GetEnvironmentVariableW(name, buffer,
                                            static_cast<DWORD>(std::size(buffer)));
  if (len > 0 && len < std::size(buffer)) {
    return std::filesystem::path(buffer);
  }
  return {};
}

}  // namespace

std::vector<std::filesystem::path> DefaultWatchedDirs() {
  std::vector<std::filesystem::path> dirs;
  auto add = [&dirs](std::filesystem::path p) {
    if (!p.empty()) dirs.push_back(std::move(p));
  };
  add(EnvDir(L"TEMP"));
  const auto appData = EnvDir(L"APPDATA");
  add(appData);
  if (!appData.empty()) {
    add(appData / L"Microsoft\\Windows\\Start Menu\\Programs\\Startup");
  }
  add(EnvDir(L"PUBLIC"));
  const auto userProfile = EnvDir(L"USERPROFILE");
  if (!userProfile.empty()) {
    add(userProfile / L"Downloads");
  }
  return dirs;
}

FileSnapshot CaptureFileSnapshot(const std::vector<std::filesystem::path> &dirs,
                                 size_t maxEntries) {
  FileSnapshot snap;
  for (const auto &dir : dirs) {
    std::error_code ec;
    if (dir.empty() || !std::filesystem::exists(dir, ec)) {
      continue;
    }
    std::filesystem::recursive_directory_iterator it(
        dir, std::filesystem::directory_options::skip_permission_denied, ec);
    std::filesystem::recursive_directory_iterator end;
    while (it != end) {
      if (snap.size() >= maxEntries) {
        break;
      }
      const auto entry = *it;
      it.increment(ec);
      if (ec) {
        ec.clear();
        continue;
      }
      std::error_code fec;
      if (!entry.is_regular_file(fec)) {
        continue;
      }
      FileMeta meta;
      meta.size = static_cast<uint64_t>(entry.file_size(fec));
      if (fec) {
        fec.clear();
        meta.size = 0;
      }
      const auto wt = std::filesystem::last_write_time(entry.path(), fec);
      meta.mtimeTicks =
          fec ? 0 : static_cast<int64_t>(wt.time_since_epoch().count());
      snap[PathToUtf8(entry.path())] = meta;
    }
  }
  return snap;
}

std::vector<EventRecord> DiffFileSnapshots(const FileSnapshot &prev,
                                           const FileSnapshot &cur,
                                           bool emitBaseline, size_t baselineCap,
                                           size_t deltaCap) {
  std::vector<EventRecord> out;
  if (emitBaseline) {
    size_t n = 0;
    for (const auto &entry : cur) {
      if (n++ >= baselineCap) break;
      out.push_back(MakeFileEvent(entry.first, entry.second, "file.observed"));
    }
    return out;
  }
  size_t changes = 0;
  for (const auto &entry : cur) {
    const auto it = prev.find(entry.first);
    if (it == prev.end()) {
      if (changes++ >= deltaCap) continue;
      out.push_back(MakeFileEvent(entry.first, entry.second, "file.create"));
    } else if (it->second.size != entry.second.size ||
               it->second.mtimeTicks != entry.second.mtimeTicks) {
      if (changes++ >= deltaCap) continue;
      out.push_back(MakeFileEvent(entry.first, entry.second, "file.modify"));
    }
  }
  for (const auto &entry : prev) {
    if (cur.find(entry.first) == cur.end()) {
      out.push_back(MakeFileEvent(entry.first, entry.second, "file.delete"));
    }
  }
  return out;
}

}  // namespace antimal
