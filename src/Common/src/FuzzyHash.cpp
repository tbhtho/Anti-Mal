#include "antimal/FuzzyHash.h"

#include <algorithm>
#include <array>

namespace antimal {
namespace {

constexpr int kSpamsumLength = 64;  // max signature1 length
constexpr int kMinBlockSize = 3;
constexpr int kRollingWindow = 7;
constexpr uint32_t kHashPrime = 0x01000193u; // FNV-1 prime
constexpr uint32_t kHashInit = 0x28021967u;  // spamsum's seed

const char *kB64 =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// 7-byte rolling window hash. Its value mod the block size is the piece-boundary
// trigger; this is what makes the hash "context-triggered" (boundaries follow
// content, not absolute offset, so an early insertion only shifts later
// boundaries locally instead of changing the whole digest).
struct RollState {
  std::array<uint8_t, kRollingWindow> window{};
  uint32_t h1 = 0, h2 = 0, h3 = 0;
  uint32_t n = 0;
};

uint32_t RollHash(RollState &s, uint8_t c) {
  s.h2 -= s.h1;
  s.h2 += static_cast<uint32_t>(kRollingWindow) * c;
  s.h1 += c;
  s.h1 -= s.window[s.n];
  s.window[s.n] = c;
  s.n++;
  if (s.n == kRollingWindow) s.n = 0;
  s.h3 = (s.h3 << 5) ^ c;
  return s.h1 + s.h2 + s.h3;
}

// FNV-style per-piece hash; reset to kHashInit at each piece boundary.
inline uint32_t SumHash(uint8_t c, uint32_t h) { return (h * kHashPrime) ^ c; }

// Collapse runs of more than 3 identical chars to exactly 3. Long identical runs
// (e.g. zero-padding) otherwise dominate the edit distance and inflate scores.
std::string EliminateSequences(const std::string &s) {
  std::string out;
  out.reserve(s.size());
  for (size_t i = 0; i < s.size(); ++i) {
    if (i >= 3 && s[i] == s[i - 1] && s[i] == s[i - 2] && s[i] == s[i - 3]) {
      continue;
    }
    out.push_back(s[i]);
  }
  return out;
}

// Do the two signatures share any substring of length kRollingWindow? ssdeep
// requires this before scoring so unrelated digests that happen to have a small
// edit distance don't score as similar.
bool HasCommonSubstring(const std::string &a, const std::string &b) {
  if (a.size() < static_cast<size_t>(kRollingWindow) ||
      b.size() < static_cast<size_t>(kRollingWindow)) {
    return false;
  }
  for (size_t i = 0; i + kRollingWindow <= a.size(); ++i) {
    const std::string needle = a.substr(i, kRollingWindow);
    if (b.find(needle) != std::string::npos) return true;
  }
  return false;
}

// Levenshtein distance with ssdeep's costs: insert=1, delete=1, replace=2.
int EditDistance(const std::string &s1, const std::string &s2) {
  constexpr int kIns = 1, kDel = 1, kRep = 2;
  const size_t n = s1.size(), m = s2.size();
  std::vector<int> prev(m + 1), cur(m + 1);
  for (size_t j = 0; j <= m; ++j) prev[j] = static_cast<int>(j) * kIns;
  for (size_t i = 1; i <= n; ++i) {
    cur[0] = static_cast<int>(i) * kDel;
    for (size_t j = 1; j <= m; ++j) {
      const int del = prev[j] + kDel;
      const int ins = cur[j - 1] + kIns;
      const int rep = prev[j - 1] + (s1[i - 1] == s2[j - 1] ? 0 : kRep);
      cur[j] = std::min(del, std::min(ins, rep));
    }
    std::swap(prev, cur);
  }
  return prev[m];
}

// Map an edit distance between two same-block-size signatures to a 0..100 score,
// then cap it by the block size so a match over a tiny amount of data can't
// claim high confidence.
int ScoreStrings(const std::string &s1raw, const std::string &s2raw,
                 uint32_t blockSize) {
  const std::string s1 = EliminateSequences(s1raw);
  const std::string s2 = EliminateSequences(s2raw);
  if (s1.empty() || s2.empty()) return 0;
  if (!HasCommonSubstring(s1, s2)) return 0;

  int score = EditDistance(s1, s2);
  // Normalize against combined length, invert (distance -> similarity), scale.
  score = static_cast<int>(static_cast<int64_t>(score) * kSpamsumLength /
                           static_cast<int64_t>(s1.size() + s2.size()));
  score = (100 * score) / kSpamsumLength;
  score = 100 - score;
  if (score < 0) score = 0;

  // Block-size cap: at the smallest block size a match represents very little
  // data, so the confidence ceiling is min(len). Each block-size doubling lifts
  // the ceiling, until it exceeds 100 and stops binding.
  const int64_t cap = static_cast<int64_t>(blockSize / kMinBlockSize) *
                      static_cast<int64_t>(std::min(s1.size(), s2.size()));
  if (static_cast<int64_t>(score) > cap) score = static_cast<int>(cap);
  if (score > 100) score = 100;
  return score;
}

struct ParsedDigest {
  bool ok = false;
  uint32_t blockSize = 0;
  std::string sig1;
  std::string sig2;
};

ParsedDigest Parse(const std::string &digest) {
  ParsedDigest p;
  const size_t c1 = digest.find(':');
  if (c1 == std::string::npos) return p;
  const size_t c2 = digest.find(':', c1 + 1);
  if (c2 == std::string::npos) return p;
  const std::string bs = digest.substr(0, c1);
  if (bs.empty()) return p;
  uint64_t blockSize = 0;
  for (char ch : bs) {
    if (ch < '0' || ch > '9') return p;
    blockSize = blockSize * 10 + static_cast<uint32_t>(ch - '0');
    if (blockSize > 0xFFFFFFFFull) return p;
  }
  if (blockSize == 0) return p;
  p.ok = true;
  p.blockSize = static_cast<uint32_t>(blockSize);
  p.sig1 = digest.substr(c1 + 1, c2 - c1 - 1);
  p.sig2 = digest.substr(c2 + 1);
  return p;
}

} // namespace

std::string ComputeCtph(const std::vector<uint8_t> &data) {
  const size_t len = data.size();
  if (len == 0) return std::string();

  // Pick the initial block size so the primary signature lands near full length.
  // Cap the doubling at 2^30 so `blockSize` and `blockSize * 2` (below) always
  // stay within uint32 — without the cap an absurdly large input (>64 GiB) would
  // overflow blockSize, wrap, and spin the loop forever. Real inputs (a file
  // loaded into a vector) never approach the cap, so digests are unchanged.
  uint32_t blockSize = kMinBlockSize;
  while (blockSize < 0x40000000u &&
         static_cast<uint64_t>(blockSize) * kSpamsumLength < len) {
    blockSize *= 2;
  }

  std::string sig1, sig2;
  for (;;) {
    sig1.clear();
    sig2.clear();
    RollState roll;
    uint32_t h1 = kHashInit; // piece hash feeding signature1 (block size)
    uint32_t h2 = kHashInit; // piece hash feeding signature2 (2x block size)
    uint32_t lastRh = 0;
    for (size_t i = 0; i < len; ++i) {
      const uint8_t c = data[i];
      h1 = SumHash(c, h1);
      h2 = SumHash(c, h2);
      lastRh = RollHash(roll, c);
      if (lastRh % blockSize == blockSize - 1) {
        if (sig1.size() < static_cast<size_t>(kSpamsumLength - 1)) {
          sig1.push_back(kB64[h1 % 64]);
          h1 = kHashInit;
        }
      }
      const uint64_t bs2 = static_cast<uint64_t>(blockSize) * 2; // overflow-safe
      if (lastRh % bs2 == bs2 - 1) {
        if (sig2.size() < static_cast<size_t>(kSpamsumLength / 2 - 1)) {
          sig2.push_back(kB64[h2 % 64]);
          h2 = kHashInit;
        }
      }
    }
    // Flush the trailing partial piece so the digest ends with the hash of the
    // final block (matches spamsum's `if (h != 0)` tail).
    if (lastRh != 0) {
      sig1.push_back(kB64[h1 % 64]);
      sig2.push_back(kB64[h2 % 64]);
    }
    // If the primary signature came out too short, the block size was too big to
    // characterize this file — halve it and try again.
    if (blockSize > static_cast<uint32_t>(kMinBlockSize) &&
        sig1.size() < static_cast<size_t>(kSpamsumLength / 2)) {
      blockSize /= 2;
      continue;
    }
    break;
  }

  return std::to_string(blockSize) + ":" + sig1 + ":" + sig2;
}

int CompareCtph(const std::string &a, const std::string &b) {
  const ParsedDigest pa = Parse(a);
  const ParsedDigest pb = Parse(b);
  if (!pa.ok || !pb.ok) return -1;

  // Compare only signatures computed at the same effective block size. Each
  // digest carries sigs at {bs, 2*bs}; line those up across the two digests.
  if (pa.blockSize == pb.blockSize) {
    const int s1 = ScoreStrings(pa.sig1, pb.sig1, pa.blockSize);
    const int s2 = ScoreStrings(pa.sig2, pb.sig2, pa.blockSize * 2);
    return std::max(s1, s2);
  }
  if (pa.blockSize == pb.blockSize * 2) {
    return ScoreStrings(pa.sig1, pb.sig2, pa.blockSize);
  }
  if (pb.blockSize == pa.blockSize * 2) {
    return ScoreStrings(pa.sig2, pb.sig1, pb.blockSize);
  }
  return 0; // block sizes too far apart to compare
}

} // namespace antimal
