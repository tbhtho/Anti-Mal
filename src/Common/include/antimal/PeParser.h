#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

namespace antimal {

struct PeInfo {
  bool isPe = false;
  uint16_t machine = 0;
  uint16_t numberOfSections = 0;
  uint16_t subsystem = 0;
  std::vector<std::string> imports;
  // pefile-compatible import hash: MD5 of the comma-joined, lowercased
  // "libname_no_ext.funcname" tokens in import-table order (ordinal imports
  // become "ordN"). Empty when the PE imports nothing. Lets a sample be pivoted
  // against VT/threat-intel by import fingerprint even when the file hash is
  // unique (the classic way to cluster a malware family across recompiles).
  std::string imphash;
};

PeInfo ParsePe(const std::vector<uint8_t> &data);
PeInfo ParsePeFile(const std::filesystem::path &path);
bool HasAuthenticodeSignature(const std::filesystem::path &path);

// Pure imphash core, exposed for testing. `imports` is the ordered list of
// (dllName, importName) exactly as they appear in the import table; importName
// must be "ordN" for ordinal imports. Applies the canonical pefile rules
// (lowercase, strip a trailing .dll/.ocx/.sys from the lib, join with ',') and
// returns the MD5, or "" for no imports.
std::string ComputeImphash(
    const std::vector<std::pair<std::string, std::string>> &imports);

} // namespace antimal
