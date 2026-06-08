#include "antimal/PeParser.h"

#include "antimal/Crypto.h"
#include "antimal/FileUtil.h"

#include <Windows.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <stdexcept>

namespace antimal {
namespace {

template <typename T> const T *PtrAt(const std::vector<uint8_t> &data, size_t offset) {
  if (offset > data.size() || sizeof(T) > data.size() - offset) {
    return nullptr;
  }
  return reinterpret_cast<const T *>(data.data() + offset);
}

const IMAGE_SECTION_HEADER *Sections(const std::vector<uint8_t> &data,
                                     const IMAGE_NT_HEADERS *nt) {
  const auto sectionOffset =
      reinterpret_cast<const uint8_t *>(IMAGE_FIRST_SECTION(nt)) - data.data();
  return PtrAt<IMAGE_SECTION_HEADER>(data, sectionOffset);
}

size_t RvaToOffset(const std::vector<uint8_t> &data, const IMAGE_NT_HEADERS *nt,
                   DWORD rva) {
  const IMAGE_SECTION_HEADER *sections = Sections(data, nt);
  if (!sections) {
    return 0;
  }
  for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
    const DWORD virtualSize = std::max(sections[i].Misc.VirtualSize, sections[i].SizeOfRawData);
    if (rva >= sections[i].VirtualAddress &&
        rva < sections[i].VirtualAddress + virtualSize) {
      const DWORD delta = rva - sections[i].VirtualAddress;
      const DWORD offset = sections[i].PointerToRawData + delta;
      if (offset < data.size()) {
        return offset;
      }
    }
  }
  if (rva < data.size()) {
    return rva;
  }
  return 0;
}

std::string ReadAsciiZ(const std::vector<uint8_t> &data, size_t offset) {
  std::string value;
  while (offset < data.size() && data[offset] != 0) {
    const char c = static_cast<char>(data[offset++]);
    if (c >= 0x20 && c < 0x7f) {
      value.push_back(c);
    } else {
      value.push_back('?');
    }
  }
  return value;
}

// Shannon entropy (bits/byte, 0..8) over a raw byte range. Local copy so the PE
// parser doesn't depend on the higher-level Scanner.
double ByteEntropy(const uint8_t *p, size_t n) {
  if (!p || n == 0) {
    return 0.0;
  }
  std::array<size_t, 256> freq{};
  for (size_t i = 0; i < n; ++i) {
    ++freq[p[i]];
  }
  double entropy = 0.0;
  const double len = static_cast<double>(n);
  for (size_t count : freq) {
    if (!count) {
      continue;
    }
    const double pr = static_cast<double>(count) / len;
    entropy -= pr * std::log2(pr);
  }
  return entropy;
}

// The 8-byte section name is space/NUL padded and not guaranteed terminated;
// stop at the first NUL and sanitize non-printables.
std::string SectionName(const BYTE name[IMAGE_SIZEOF_SHORT_NAME]) {
  std::string s;
  for (int i = 0; i < IMAGE_SIZEOF_SHORT_NAME && name[i] != 0; ++i) {
    const char c = static_cast<char>(name[i]);
    s.push_back((c >= 0x20 && c < 0x7f) ? c : '?');
  }
  return s;
}

} // namespace

std::string ComputeImphash(
    const std::vector<std::pair<std::string, std::string>> &imports) {
  std::string joined;
  for (const auto &entry : imports) {
    std::string lib = ToLowerAscii(entry.first);
    // pefile strips a single trailing .dll/.ocx/.sys before hashing.
    const size_t dot = lib.find_last_of('.');
    if (dot != std::string::npos) {
      const std::string ext = lib.substr(dot + 1);
      if (ext == "dll" || ext == "ocx" || ext == "sys") {
        lib.erase(dot);
      }
    }
    if (!joined.empty()) {
      joined.push_back(',');
    }
    joined += lib;
    joined.push_back('.');
    joined += ToLowerAscii(entry.second);
  }
  if (joined.empty()) {
    return std::string();
  }
  return Md5Hex(std::vector<uint8_t>(joined.begin(), joined.end()));
}

PeInfo ParsePe(const std::vector<uint8_t> &data) {
  PeInfo info;
  const auto *dos = PtrAt<IMAGE_DOS_HEADER>(data, 0);
  if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0) {
    return info;
  }

  const auto ntOffset = static_cast<size_t>(dos->e_lfanew);
  const auto *nt = PtrAt<IMAGE_NT_HEADERS>(data, ntOffset);
  if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) {
    return info;
  }

  info.isPe = true;
  info.machine = nt->FileHeader.Machine;
  info.numberOfSections = nt->FileHeader.NumberOfSections;
  info.timeDateStamp = nt->FileHeader.TimeDateStamp;

  // Section table + per-section entropy (parsed before the import-directory
  // early-outs below, so a PE with no imports still reports its sections).
  uint64_t maxRawEnd = 0;
  if (const IMAGE_SECTION_HEADER *first = Sections(data, nt)) {
    const auto firstOffset =
        static_cast<size_t>(reinterpret_cast<const uint8_t *>(first) - data.data());
    const WORD count = nt->FileHeader.NumberOfSections;
    for (WORD i = 0; i < count && i < 96; ++i) {
      const auto *sh = PtrAt<IMAGE_SECTION_HEADER>(
          data, firstOffset + static_cast<size_t>(i) * sizeof(IMAGE_SECTION_HEADER));
      if (!sh) {
        break;
      }
      PeSection sec;
      sec.name = SectionName(sh->Name);
      sec.virtualSize = sh->Misc.VirtualSize;
      sec.rawSize = sh->SizeOfRawData;
      sec.characteristics = sh->Characteristics;
      sec.executable = (sh->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
      sec.writable = (sh->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
      size_t off = sh->PointerToRawData;
      size_t len = sh->SizeOfRawData;
      if (sh->SizeOfRawData > 0) {
        maxRawEnd = std::max<uint64_t>(
            maxRawEnd, static_cast<uint64_t>(sh->PointerToRawData) + sh->SizeOfRawData);
      }
      if (off < data.size()) {
        if (len > data.size() - off) {
          len = data.size() - off;
        }
        sec.entropy = ByteEntropy(data.data() + off, len);
      }
      info.sections.push_back(std::move(sec));
    }
  }

  // Overlay: bytes appended after the last section's raw data. Common in
  // installers, and a frequent home for appended encrypted/packed payloads. For
  // a SIGNED PE this region also holds the Authenticode certificate, so the
  // Scanner only treats a high-entropy overlay on an UNSIGNED file as a tell.
  if (maxRawEnd > 0 && data.size() > maxRawEnd) {
    info.overlayOffset = maxRawEnd;
    info.overlaySize = static_cast<uint64_t>(data.size()) - maxRawEnd;
    info.overlayEntropy = ByteEntropy(
        data.data() + maxRawEnd, static_cast<size_t>(info.overlaySize));
  }

  DWORD importRva = 0;
  DWORD importSize = 0;
  if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
      nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    info.subsystem = nt->OptionalHeader.Subsystem;
    importRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    importSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
  }

  if (!importRva || !importSize) {
    return info;
  }

  size_t importOffset = RvaToOffset(data, nt, importRva);
  if (!importOffset) {
    return info;
  }

  // Imports in raw import-table order (named + ordinal), used to compute the
  // pefile-compatible imphash. info.imports keeps its existing contract (sorted,
  // deduped, named-only) for the tagger / IOC consumers.
  std::vector<std::pair<std::string, std::string>> orderedImports;

  for (size_t descIndex = 0; descIndex < 512; ++descIndex) {
    const auto *desc = PtrAt<IMAGE_IMPORT_DESCRIPTOR>(
        data, importOffset + descIndex * sizeof(IMAGE_IMPORT_DESCRIPTOR));
    if (!desc || (desc->OriginalFirstThunk == 0 && desc->FirstThunk == 0)) {
      break;
    }

    const std::string dll = ToLowerAscii(ReadAsciiZ(data, RvaToOffset(data, nt, desc->Name)));
    const DWORD thunkRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
    size_t thunkOffset = RvaToOffset(data, nt, thunkRva);
    if (!thunkOffset) {
      continue;
    }

    const bool is64 = nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    for (size_t thunkIndex = 0; thunkIndex < 4096; ++thunkIndex) {
      uint64_t thunk = 0;
      if (is64) {
        const auto *t = PtrAt<IMAGE_THUNK_DATA64>(
            data, thunkOffset + thunkIndex * sizeof(IMAGE_THUNK_DATA64));
        if (!t || t->u1.AddressOfData == 0) {
          break;
        }
        thunk = t->u1.AddressOfData;
        if (IMAGE_SNAP_BY_ORDINAL64(thunk)) {
          orderedImports.emplace_back(
              dll, "ord" + std::to_string(IMAGE_ORDINAL64(thunk)));
          continue;
        }
      } else {
        const auto *t = PtrAt<IMAGE_THUNK_DATA32>(
            data, thunkOffset + thunkIndex * sizeof(IMAGE_THUNK_DATA32));
        if (!t || t->u1.AddressOfData == 0) {
          break;
        }
        thunk = t->u1.AddressOfData;
        if (IMAGE_SNAP_BY_ORDINAL32(static_cast<DWORD>(thunk))) {
          orderedImports.emplace_back(
              dll,
              "ord" + std::to_string(IMAGE_ORDINAL32(static_cast<DWORD>(thunk))));
          continue;
        }
      }

      const size_t nameOffset = RvaToOffset(data, nt, static_cast<DWORD>(thunk));
      const auto *importByName = PtrAt<IMAGE_IMPORT_BY_NAME>(data, nameOffset);
      if (!importByName) {
        continue;
      }
      std::string name = ReadAsciiZ(data, nameOffset + offsetof(IMAGE_IMPORT_BY_NAME, Name));
      if (!name.empty()) {
        info.imports.push_back(dll + "!" + name);
        orderedImports.emplace_back(dll, name);
      }
    }
  }

  info.imphash = ComputeImphash(orderedImports);
  std::sort(info.imports.begin(), info.imports.end());
  info.imports.erase(std::unique(info.imports.begin(), info.imports.end()), info.imports.end());
  return info;
}

PeInfo ParsePeFile(const std::filesystem::path &path) {
  return ParsePe(ReadAllBytes(path));
}

bool HasAuthenticodeSignature(const std::filesystem::path &path) {
  WINTRUST_FILE_INFO fileInfo{};
  fileInfo.cbStruct = sizeof(fileInfo);
  const std::wstring wide = path.wstring();
  fileInfo.pcwszFilePath = wide.c_str();

  WINTRUST_DATA trustData{};
  trustData.cbStruct = sizeof(trustData);
  trustData.dwUIChoice = WTD_UI_NONE;
  trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
  trustData.dwUnionChoice = WTD_CHOICE_FILE;
  trustData.dwStateAction = WTD_STATEACTION_VERIFY;
  trustData.pFile = &fileInfo;
  trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

  GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  const LONG status = WinVerifyTrust(nullptr, &action, &trustData);
  trustData.dwStateAction = WTD_STATEACTION_CLOSE;
  WinVerifyTrust(nullptr, &action, &trustData);
  return status == ERROR_SUCCESS;
}

} // namespace antimal
