#include "antimal/PeParser.h"

#include "antimal/FileUtil.h"

#include <Windows.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

#include <algorithm>
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

} // namespace

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
      }
    }
  }

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
