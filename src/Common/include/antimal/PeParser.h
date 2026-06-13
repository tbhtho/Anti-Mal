#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

namespace antimal {

// One PE section header + the Shannon entropy of its raw bytes. A high-entropy
// (> ~7.0) section that is also executable is the classic packer/crypter tell --
// it lets "packed" be an evidence-backed finding instead of a whole-file guess.
struct PeSection {
  std::string name;
  uint32_t virtualSize = 0;
  uint32_t rawSize = 0;
  uint32_t characteristics = 0; // IMAGE_SCN_* flags (exec/read/write/...)
  double entropy = 0.0;
  bool executable = false; // IMAGE_SCN_MEM_EXECUTE
  bool writable = false;   // IMAGE_SCN_MEM_WRITE
};

// RT_VERSION StringFileInfo fields. Every string is empty when absent; `present`
// is true only when a VS_VERSIONINFO resource was successfully parsed. The
// OriginalFilename is the masquerade tell -- when it disagrees with the on-disk
// name the file was renamed (a common delivery trick).
struct PeVersionInfo {
  bool present = false;
  std::string companyName;
  std::string productName;
  std::string fileDescription;
  std::string originalFilename;
  std::string internalName;
  std::string fileVersion;
  std::string productVersion;
  std::string legalCopyright;
};

struct PeInfo {
  bool isPe = false;
  bool isDll = false; // IMAGE_FILE_DLL in FileHeader.Characteristics
  uint16_t machine = 0;
  uint16_t numberOfSections = 0;
  uint16_t subsystem = 0;
  uint32_t timeDateStamp = 0; // IMAGE_FILE_HEADER.TimeDateStamp (unix epoch secs)
  std::vector<PeSection> sections;
  uint64_t overlayOffset = 0;  // file offset where post-last-section data begins
  uint64_t overlaySize = 0;    // appended bytes (includes any Authenticode cert)
  double overlayEntropy = 0.0; // Shannon entropy of the overlay region
  std::vector<std::string> imports;
  // pefile-compatible import hash: MD5 of the comma-joined, lowercased
  // "libname_no_ext.funcname" tokens in import-table order (ordinal imports
  // become "ordN"). Empty when the PE imports nothing. Lets a sample be pivoted
  // against VT/threat-intel by import fingerprint even when the file hash is
  // unique (the classic way to cluster a malware family across recompiles).
  std::string imphash;

  // --- T47 depth (all default to "absent"; pure-static, no boot) ---

  // .NET / CLR: DataDirectory[14] (COM descriptor / Cor20 header) present.
  // Managed samples (most modern stealers/RATs) route differently downstream.
  bool isDotNet = false;
  std::string dotNetRuntimeVersion; // "major.minor" from IMAGE_COR20_HEADER, else ""

  // Export table (DataDirectory[0]). `exportName` is the module's internal name.
  // A non-DLL that exports functions is an unusual reflective-loader/masquerade
  // tell. `exports` are the named symbols, sorted/deduped, capped.
  std::string exportName;
  std::vector<std::string> exports;

  // TLS callbacks (DataDirectory[9]). Code that runs BEFORE the entry point --
  // a classic anti-analysis / unpacker-stub tell. Count of non-null callbacks.
  uint32_t tlsCallbackCount = 0;

  // VERSIONINFO (DataDirectory[2] -> RT_VERSION resource).
  PeVersionInfo versionInfo;

  // Debug directory (DataDirectory[6]). The CodeView (RSDS) PDB path leaks
  // internal build paths/usernames -- a strong IOC + dev fingerprint.
  std::string pdbPath;
  uint32_t debugEntryCount = 0;

  // Rich header (MSVC build provenance in the DOS stub). `richHash` is the MD5
  // of the XOR-decoded @comp.id payload (pefile "richhash") -- clusters families
  // by toolchain; its absence on an otherwise-MSVC PE is a tamper tell.
  bool hasRichHeader = false;
  std::string richHash;
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
