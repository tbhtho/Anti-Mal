#include "antimal/FileSystemTelemetry.h"

#include "antimal/Crypto.h"    // Sha256Hex
#include "antimal/FileUtil.h"  // UtcNowIso8601, PathToUtf8, Utf8ToWide
#include "antimal/Scanner.h"   // IdentifyFileType (magic-byte type label)

#include <Windows.h>

#include <algorithm>
#include <cstdlib>
#include <optional>

namespace antimal {

namespace {

// Reads up to `cap` bytes of a file with a tolerant share mode so a drop that is
// still open for writing (the common case mid-detonation) can still be read.
// `truncated` is set when the file was larger than `cap` and the read stopped at
// the cap. Returns std::nullopt only when the file could not be opened at all
// (locked with no shared read, deleted, ACL) -- the caller treats that as
// "locked", never as an error.
std::optional<std::vector<uint8_t>> ReadFileHeadShared(const std::wstring &widePath,
                                                       uint64_t cap,
                                                       bool *truncated) {
  if (truncated) *truncated = false;
  // FILE_FLAG_OPEN_REPARSE_POINT: defense-in-depth so even if a reparse point
  // slipped past the snapshot's symlink skip, we open the link itself rather
  // than following it to an attacker-chosen target. Ignored for normal files.
  HANDLE h = CreateFileW(widePath.c_str(), GENERIC_READ,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         nullptr, OPEN_EXISTING,
                         FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT,
                         nullptr);
  if (h == INVALID_HANDLE_VALUE) {
    return std::nullopt;
  }
  std::vector<uint8_t> bytes;
  bytes.reserve(static_cast<size_t>(std::min<uint64_t>(cap, 1u << 20)));
  uint8_t buf[64 * 1024];
  uint64_t total = 0;
  for (;;) {
    const uint64_t remaining = cap - total;
    if (remaining == 0) {
      // Hit the cap. Peek one more byte to learn whether the file is bigger.
      DWORD probe = 0;
      uint8_t one = 0;
      if (ReadFile(h, &one, 1, &probe, nullptr) && probe == 1 && truncated) {
        *truncated = true;
      }
      break;
    }
    const DWORD want =
        static_cast<DWORD>(std::min<uint64_t>(remaining, sizeof(buf)));
    DWORD got = 0;
    if (!ReadFile(h, buf, want, &got, nullptr)) {
      CloseHandle(h);
      return std::nullopt;  // read fault after open -> treat as unreadable
    }
    if (got == 0) {
      break;  // EOF
    }
    bytes.insert(bytes.end(), buf, buf + got);
    total += got;
  }
  CloseHandle(h);
  return bytes;
}


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
      // Skip symlinks/junctions: the watched dirs are sample-writable, so a
      // dropped "file" could be a reparse point to e.g. \System32\config\SAM.
      // is_symlink uses symlink_status (does NOT follow), and is_regular_file
      // DOES follow -- so without this a SYSTEM agent would read+hash+ship the
      // target. The recursive iterator already doesn't follow directory symlinks
      // (follow_directory_symlink is off).
      if (entry.is_symlink(fec)) {
        fec.clear();
        continue;
      }
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

std::string ClassifyDroppedFileBytes(const std::vector<uint8_t> &head) {
  if (head.empty()) {
    return "empty";
  }
  std::string type = IdentifyFileType(head);
  // IdentifyFileType returns "" for bytes that match no known signature; surface
  // that as "data" so the report cell is never blank for a file that exists.
  return type.empty() ? "data" : type;
}

void EnrichDroppedFileEvent(EventRecord &event) {
  if (event.target.empty()) {
    return;
  }
  // Parse the size the diff already recorded; it lets us skip the read entirely
  // for an oversize drop (mark + move on) without opening the file.
  uint64_t size = 0;
  if (const auto it = event.details.find("size"); it != event.details.end()) {
    size = std::strtoull(it->second.c_str(), nullptr, 10);
  }
  if (size > kMaxHashBytes) {
    event.details["hashSkipped"] = "size";
    event.details["fileType"] = "(large, unhashed)";
    return;
  }

  const std::wstring widePath = Utf8ToWide(event.target);
  bool truncated = false;
  const auto head =
      ReadFileHeadShared(widePath, kMaxHashBytes, &truncated);
  if (!head) {
    // Locked / deleted / ACL-denied -- emit the event anyway with a marker so
    // the operator sees the drop happened even though we couldn't read it.
    event.details["hashSkipped"] = "locked";
    return;
  }
  if (truncated) {
    // The recorded size lied (file grew past the cap between snapshot + read).
    event.details["hashSkipped"] = "size";
    event.details["fileType"] = "(large, unhashed)";
    return;
  }
  // Type from the (already-read) bytes, then the full-content sha256. Reusing the
  // static pipeline's magic-byte detector keeps the labels consistent end-to-end.
  event.details["fileType"] = ClassifyDroppedFileBytes(*head);
  event.details["sha256"] = Sha256Hex(*head);
}

}  // namespace antimal
