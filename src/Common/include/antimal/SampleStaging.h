#pragma once

// SampleStaging - content-addressed immutable staging for the detonation input.
//
// The run directory must hold a private, immutable snapshot of the sample: the
// disk-delivery path attaches `in/<sample>` as a read-only block device and the
// approval/evidence trail must be bound to BYTES, not to a mutable filename.
//
// A raw hardlink to the operator's source file would satisfy neither (the source
// stays writable; a hardlink is not a snapshot). This module therefore stages
// through an immutable cache:
//
//   source --(one copy, hashed)--> <workspace>/_cache/samples/<sha256>.bin
//                                     (read-only, content-addressed, never
//                                      modified after publication)
//          --(hardlink in the same volume, else copy)--> <run>/in/<name>
//
// Lifetime/identity guarantees this relies on:
//   * the cache entry name IS its sha256, and it is published atomically
//     (temp file -> rename) only after the written bytes were re-hashed;
//   * cache entries are marked read-only; a reuse that finds the attribute gone
//     re-hashes before trusting the entry and rebuilds it on mismatch;
//   * a staged run file is a hardlink to an immutable inode, so later source
//     edits cannot change what the run approved; deleting a run's link (or
//     pruning the cache) never affects the other link;
//   * if hardlinks are unavailable (cross-volume staging) the run gets a private
//     copy FROM THE IMMUTABLE CACHE, never from the mutable source.
//
// The cache is bounded by `maxCacheBytes` (oldest entries pruned first). Pruning
// only removes cache links; a run's own hardlink keeps its bytes alive.
//
// Trust boundary: a hardlinked run file and its cache entry share one inode, so
// anything with write access to the workspace can alter both -- exactly as it
// could alter the previous per-run copy. The cache's read-only attribute is the
// accidental-modification guard, not a security boundary; the workspace is
// host-side and trusted.

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>

namespace antimal {

struct StageSampleResult {
  bool ok = false;
  std::filesystem::path stagedPath;
  std::string sha256;      // identity of the staged BYTES
  uint64_t bytes = 0;
  bool cacheHit = false;   // the cache already held this content
  bool hardLinked = false; // staged as a hardlink (no data copy into the run)
  bool repaired = false;   // a bad cache entry was detected and rebuilt
  std::string error;
};

// `progress` (optional) receives short human-readable stage lines
// ("hashing", "copying <n> MiB", "linking") for live operator visibility.
StageSampleResult StageSampleImmutable(
    const std::filesystem::path &sample,
    const std::filesystem::path &runInDir,
    const std::filesystem::path &cacheDir,
    uint64_t maxCacheBytes = 0,
    const std::function<void(const std::string &)> &progress = {});

// Default cache location / budget (config overrides these).
constexpr uint64_t kDefaultStagingCacheBytes = 8ull * 1024 * 1024 * 1024;

} // namespace antimal
