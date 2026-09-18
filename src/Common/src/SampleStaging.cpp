#include "antimal/SampleStaging.h"

#include "antimal/Crypto.h"
#include "antimal/FileUtil.h"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <fstream>
#include <system_error>
#include <vector>

namespace antimal {
namespace {

constexpr size_t kCopyChunk = 1u << 20; // 1 MiB

// Unique per staging attempt: concurrent stages of the same content must not
// share a temp file (the first test of this caught the collision).
std::filesystem::path UniqueTempPath(const std::filesystem::path &cacheDir,
                                     const std::string &sha256) {
  static std::atomic<uint64_t> counter{0};
  const uint64_t n = counter.fetch_add(1);
  return cacheDir / (sha256 + "." + std::to_string(GetCurrentProcessId()) +
                     "." + std::to_string(GetCurrentThreadId()) + "." +
                     std::to_string(n) + ".tmp");
}

bool IsReadOnly(const std::filesystem::path &path) {
  const DWORD attrs = GetFileAttributesW(path.c_str());
  return attrs != INVALID_FILE_ATTRIBUTES &&
         (attrs & FILE_ATTRIBUTE_READONLY) != 0;
}

bool SetReadOnly(const std::filesystem::path &path, bool readOnly) {
  DWORD attrs = GetFileAttributesW(path.c_str());
  if (attrs == INVALID_FILE_ATTRIBUTES) {
    return false;
  }
  if (readOnly) {
    attrs |= FILE_ATTRIBUTE_READONLY;
  } else {
    attrs &= ~static_cast<DWORD>(FILE_ATTRIBUTE_READONLY);
  }
  return SetFileAttributesW(path.c_str(), attrs) != FALSE;
}

// Copy `from` -> `to` with progress ticks. Returns false on any I/O error.
bool CopyWithProgress(const std::filesystem::path &from,
                      const std::filesystem::path &to, uint64_t totalBytes,
                      const std::function<void(const std::string &)> &progress) {
  std::ifstream in(from, std::ios::binary);
  if (!in) {
    return false;
  }
  std::ofstream out(to, std::ios::binary | std::ios::trunc);
  if (!out) {
    return false;
  }
  std::vector<char> buf(kCopyChunk);
  uint64_t copied = 0;
  while (in) {
    in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
    const std::streamsize got = in.gcount();
    if (got <= 0) {
      break;
    }
    out.write(buf.data(), got);
    if (!out) {
      return false;
    }
    copied += static_cast<uint64_t>(got);
    if (progress != nullptr && totalBytes > 0 &&
        copied % (64ull * 1024 * 1024) < static_cast<uint64_t>(got)) {
      const unsigned pct =
          static_cast<unsigned>(copied * 100ull / totalBytes);
      progress("staging " + std::to_string(pct) + "%");
    }
  }
  out.flush();
  return static_cast<bool>(out);
}

// Delete oldest cache entries (by last-write time) until the directory is
// within `maxBytes`. Only `.bin` entries are considered; a run's hardlink into
// a pruned entry keeps its own bytes (Windows link semantics).
void PruneCache(const std::filesystem::path &cacheDir, uint64_t maxBytes,
                const std::filesystem::path &keep) {
  if (maxBytes == 0) {
    return;
  }
  std::error_code ec;
  struct Entry {
    std::filesystem::path path;
    uint64_t bytes = 0;
    std::filesystem::file_time_type when{};
  };
  std::vector<Entry> entries;
  uint64_t total = 0;
  for (const auto &e : std::filesystem::directory_iterator(cacheDir, ec)) {
    if (!e.is_regular_file(ec)) {
      continue;
    }
    if (e.path().extension() != L".bin") {
      continue;
    }
    const uint64_t size = std::filesystem::file_size(e.path(), ec);
    total += size;
    entries.push_back({e.path(), size, e.last_write_time(ec)});
  }
  if (total <= maxBytes) {
    return;
  }
  std::sort(entries.begin(), entries.end(),
            [](const Entry &a, const Entry &b) { return a.when < b.when; });
  for (const Entry &entry : entries) {
    if (total <= maxBytes) {
      break;
    }
    if (entry.path == keep) {
      continue;
    }
    SetReadOnly(entry.path, false); // a read-only file cannot be deleted
    if (std::filesystem::remove(entry.path, ec)) {
      total -= entry.bytes;
    }
  }
}

} // namespace

StageSampleResult StageSampleImmutable(
    const std::filesystem::path &sample,
    const std::filesystem::path &runInDir,
    const std::filesystem::path &cacheDir, uint64_t maxCacheBytes,
    const std::function<void(const std::string &)> &progress) {
  StageSampleResult out;
  std::error_code ec;
  if (!std::filesystem::exists(sample, ec)) {
    out.error = "sample does not exist: " + PathToUtf8(sample);
    return out;
  }
  out.bytes = std::filesystem::file_size(sample, ec);
  if (ec) {
    out.error = "cannot read sample size: " + ec.message();
    return out;
  }
  if (progress != nullptr) {
    progress("hashing " + std::to_string(out.bytes) + " bytes");
  }
  out.sha256 = Sha256File(sample); // streaming: bounded memory for any size
  if (out.sha256.empty()) {
    out.error = "hashing the sample failed";
    return out;
  }

  EnsureDirectory(cacheDir);
  const std::filesystem::path cachePath = cacheDir / (out.sha256 + ".bin");
  const std::filesystem::path tempPath = UniqueTempPath(cacheDir, out.sha256);

  // --- Publish (or validate) the immutable cache entry. ---
  bool haveEntry = std::filesystem::exists(cachePath, ec);
  if (haveEntry) {
    const uint64_t cachedBytes = std::filesystem::file_size(cachePath, ec);
    if (ec || cachedBytes != out.bytes) {
      haveEntry = false; // size mismatch: not the content its name claims
      SetReadOnly(cachePath, false);
      std::filesystem::remove(cachePath, ec);
    } else if (!IsReadOnly(cachePath)) {
      // The read-only marker is how an untouched entry is recognized. Without
      // it, verify the actual bytes before trusting the name.
      if (Sha256File(cachePath) != out.sha256) {
        haveEntry = false;
        std::filesystem::remove(cachePath, ec);
      } else {
        SetReadOnly(cachePath, true);
      }
    }
  }

  if (!haveEntry) {
    if (progress != nullptr) {
      progress("copying " + std::to_string(out.bytes / (1024 * 1024)) +
               " MiB into the immutable cache");
    }
    std::filesystem::remove(tempPath, ec);
    if (!CopyWithProgress(sample, tempPath, out.bytes, progress)) {
      std::filesystem::remove(tempPath, ec);
      out.error = "copying the sample into the staging cache failed";
      return out;
    }
    // TOCTOU guard: the published identity must be the bytes we actually
    // stored. If the source changed while copying, the temp no longer matches
    // the hash computed above -- report it instead of staging unverified bytes.
    const std::string tempHash = Sha256File(tempPath);
    const uint64_t tempBytes = std::filesystem::file_size(tempPath, ec);
    if (tempHash != out.sha256 || tempBytes != out.bytes) {
      std::filesystem::remove(tempPath, ec);
      out.error =
          "sample changed while it was being staged (the source no longer "
          "matches the hash taken at approval time); re-select the file";
      return out;
    }
    SetReadOnly(tempPath, true);
    // Publish atomically. A concurrent stager may have won the race; that is
    // fine -- both entries are the same content. A loser whose temp could not
    // be promoted simply removes its own temp (it must never delete the winner).
    if (!MoveFileExW(tempPath.wstring().c_str(), cachePath.wstring().c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
      std::filesystem::remove(tempPath, ec);
      if (!std::filesystem::exists(cachePath, ec)) {
        out.error = "publishing the staging cache entry failed";
        return out;
      }
    }
  } else {
    out.cacheHit = true;
  }

  PruneCache(cacheDir, maxCacheBytes, cachePath);

  // --- Stage into the run directory. ---
  EnsureDirectory(runInDir);
  out.stagedPath = runInDir / sample.filename();
  std::filesystem::remove(out.stagedPath, ec); // hardlink target must not exist
  if (CreateHardLinkW(out.stagedPath.wstring().c_str(),
                      cachePath.wstring().c_str(), nullptr)) {
    out.hardLinked = true;
  } else {
    // Cross-volume or a filesystem without hardlinks: copy FROM THE IMMUTABLE
    // CACHE (never from the mutable source).
    if (progress != nullptr) {
      progress("copying from the staging cache into the run");
    }
    if (!CopyWithProgress(cachePath, out.stagedPath, out.bytes, nullptr)) {
      out.error = "staging from the cache into the run failed";
      return out;
    }
  }
  out.ok = true;
  return out;
}

} // namespace antimal
