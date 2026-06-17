#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Context-triggered piecewise hashing (CTPH), a.k.a. the "spamsum" algorithm
// (the same construction ssdeep uses). Unlike a cryptographic hash, a CTPH
// digest changes only LOCALLY when the input changes, so two similar files
// produce two similar digests. This is the static-triage primitive for "have I
// seen something like this before?" — clustering a sample against a corpus,
// catching trivially-repacked variants, and grouping a family.
//
// Digest format: "blocksize:signature1:signature2" where signature2 is computed
// at double the block size (so two files whose sizes differ by ~2x can still be
// compared). The alphabet is standard base64.
//
// NOTE ON COMPATIBILITY: this is a faithful implementation of the spamsum
// construction (rolling-window trigger + FNV piece hash + base64 emit + the
// has-common-substring gate, sequence-elimination, and block-size score cap that
// keep small-file matches from scoring spuriously high). It is self-consistent
// and unit-tested on its own terms (identical -> 100, similar -> high, unrelated
// -> low). Byte-for-byte interoperability with the reference `ssdeep` tool's
// database is NOT asserted here (it is not verifiable in this build environment).

namespace antimal {

// Compute the CTPH digest of a byte buffer. Returns "" for empty input.
std::string ComputeCtph(const std::vector<uint8_t> &data);

// Similarity of two CTPH digests, 0..100 (100 = effectively identical).
// Returns 0 when the digests' block sizes are not comparable (so they share no
// usable basis) or when they share no common substring. Returns -1 if either
// argument is not a well-formed "blocksize:sig1:sig2" digest.
int CompareCtph(const std::string &a, const std::string &b);

} // namespace antimal
