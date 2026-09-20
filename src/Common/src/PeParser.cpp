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
#include <cstring>
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

// ---- T47 depth: data-directory views + per-feature parsers -------------------

// A magic-aware view over the optional header so the directory parsers below are
// correct for both PE32 and PE32+ (the legacy import code reads the 64-bit
// layout directly; these newer features do not inherit that 32-bit quirk).
struct OptHeaderView {
  bool valid = false;
  bool is64 = false;
  uint64_t imageBase = 0;
  uint32_t numberOfRvaAndSizes = 0;
  const IMAGE_DATA_DIRECTORY *dirs = nullptr;
};

OptHeaderView ViewOptHeader(const IMAGE_NT_HEADERS *nt) {
  OptHeaderView v;
  const WORD magic = nt->OptionalHeader.Magic;
  if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    const auto *o =
        reinterpret_cast<const IMAGE_OPTIONAL_HEADER32 *>(&nt->OptionalHeader);
    v = {true, false, o->ImageBase, o->NumberOfRvaAndSizes, o->DataDirectory};
  } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    const auto *o =
        reinterpret_cast<const IMAGE_OPTIONAL_HEADER64 *>(&nt->OptionalHeader);
    v = {true, true, o->ImageBase, o->NumberOfRvaAndSizes, o->DataDirectory};
  }
  return v;
}

IMAGE_DATA_DIRECTORY DirOf(const OptHeaderView &opt, int index) {
  if (!opt.valid || index < 0 ||
      static_cast<uint32_t>(index) >= opt.numberOfRvaAndSizes) {
    return IMAGE_DATA_DIRECTORY{0, 0};
  }
  return opt.dirs[index];
}

// Rich header: an MSVC-linker fingerprint hidden in the DOS stub between the DOS
// header and e_lfanew. Scan forward for the "Rich" marker, read the trailing XOR
// key, walk back to the decoded "DanS" start, and MD5 the decoded payload (the
// pefile "richhash"). Empty when absent (a tamper tell on an otherwise-MSVC PE).
void ParseRichHeader(const std::vector<uint8_t> &data, size_t ntOffset,
                     PeInfo &info) {
  const size_t lo = 0x40;
  const size_t hi = std::min(ntOffset, data.size());
  if (hi <= lo + 8) {
    return;
  }
  size_t richPos = 0;
  bool foundRich = false;
  for (size_t off = lo; off + 8 <= hi; off += 4) {
    uint32_t v = 0;
    std::memcpy(&v, data.data() + off, 4);
    if (v == 0x68636952u) { // 'Rich'
      richPos = off;
      foundRich = true;
      break;
    }
  }
  if (!foundRich) {
    return;
  }
  uint32_t key = 0;
  std::memcpy(&key, data.data() + richPos + 4, 4);
  size_t dansPos = 0;
  bool foundDans = false;
  for (size_t p = richPos; p >= lo + 4; p -= 4) {
    uint32_t enc = 0;
    std::memcpy(&enc, data.data() + p - 4, 4);
    if ((enc ^ key) == 0x536E6144u) { // 'DanS'
      dansPos = p - 4;
      foundDans = true;
      break;
    }
    if (p < lo + 8) {
      break; // guard against size_t underflow on the next decrement
    }
  }
  if (!foundDans) {
    return;
  }
  std::vector<uint8_t> clear;
  clear.reserve(richPos - dansPos);
  for (size_t off = dansPos; off + 4 <= richPos; off += 4) {
    uint32_t enc = 0;
    std::memcpy(&enc, data.data() + off, 4);
    const uint32_t dec = enc ^ key;
    clear.push_back(static_cast<uint8_t>(dec & 0xFF));
    clear.push_back(static_cast<uint8_t>((dec >> 8) & 0xFF));
    clear.push_back(static_cast<uint8_t>((dec >> 16) & 0xFF));
    clear.push_back(static_cast<uint8_t>((dec >> 24) & 0xFF));
  }
  info.hasRichHeader = true;
  info.richHash = Md5Hex(clear);
}

// Export table (DataDirectory[0]): the module's internal name + its named export
// symbols (sorted/deduped, capped). A non-DLL exporting functions is unusual.
void ParseExports(const std::vector<uint8_t> &data, const IMAGE_NT_HEADERS *nt,
                  const OptHeaderView &opt, PeInfo &info) {
  const IMAGE_DATA_DIRECTORY d = DirOf(opt, IMAGE_DIRECTORY_ENTRY_EXPORT);
  if (!d.VirtualAddress) {
    return;
  }
  const auto *exp =
      PtrAt<IMAGE_EXPORT_DIRECTORY>(data, RvaToOffset(data, nt, d.VirtualAddress));
  if (!exp) {
    return;
  }
  if (exp->Name) {
    info.exportName = ReadAsciiZ(data, RvaToOffset(data, nt, exp->Name));
  }
  const size_t namesOff = RvaToOffset(data, nt, exp->AddressOfNames);
  if (namesOff && exp->NumberOfNames) {
    const DWORD cap = std::min<DWORD>(exp->NumberOfNames, 4096);
    for (DWORD i = 0; i < cap; ++i) {
      const auto *nameRva = PtrAt<DWORD>(data, namesOff + i * sizeof(DWORD));
      if (!nameRva) {
        break;
      }
      std::string nm = ReadAsciiZ(data, RvaToOffset(data, nt, *nameRva));
      if (!nm.empty()) {
        info.exports.push_back(std::move(nm));
      }
    }
    std::sort(info.exports.begin(), info.exports.end());
    info.exports.erase(std::unique(info.exports.begin(), info.exports.end()),
                       info.exports.end());
  }
}

// TLS callbacks (DataDirectory[9]): count non-null entries in AddressOfCallBacks
// (a VA -> RVA via ImageBase). Callbacks run before the entry point.
void ParseTls(const std::vector<uint8_t> &data, const IMAGE_NT_HEADERS *nt,
              const OptHeaderView &opt, PeInfo &info) {
  const IMAGE_DATA_DIRECTORY d = DirOf(opt, IMAGE_DIRECTORY_ENTRY_TLS);
  if (!d.VirtualAddress) {
    return;
  }
  const size_t off = RvaToOffset(data, nt, d.VirtualAddress);
  uint64_t callbacksVa = 0;
  if (opt.is64) {
    const auto *t = PtrAt<IMAGE_TLS_DIRECTORY64>(data, off);
    if (!t) {
      return;
    }
    callbacksVa = t->AddressOfCallBacks;
  } else {
    const auto *t = PtrAt<IMAGE_TLS_DIRECTORY32>(data, off);
    if (!t) {
      return;
    }
    callbacksVa = t->AddressOfCallBacks;
  }
  if (callbacksVa <= opt.imageBase) {
    return;
  }
  size_t cbOff =
      RvaToOffset(data, nt, static_cast<DWORD>(callbacksVa - opt.imageBase));
  if (!cbOff) {
    return;
  }
  uint32_t count = 0;
  for (uint32_t i = 0; i < 256; ++i) {
    uint64_t entry = 0;
    if (opt.is64) {
      const auto *e = PtrAt<uint64_t>(data, cbOff + i * sizeof(uint64_t));
      if (!e) {
        break;
      }
      entry = *e;
    } else {
      const auto *e = PtrAt<uint32_t>(data, cbOff + i * sizeof(uint32_t));
      if (!e) {
        break;
      }
      entry = *e;
    }
    if (entry == 0) {
      break;
    }
    ++count;
  }
  info.tlsCallbackCount = count;
}

// .NET / CLR (DataDirectory[14]): presence of a Cor20 header marks a managed
// image; we surface its runtime version (major.minor).
void ParseDotNet(const std::vector<uint8_t> &data, const IMAGE_NT_HEADERS *nt,
                 const OptHeaderView &opt, PeInfo &info) {
  const IMAGE_DATA_DIRECTORY d = DirOf(opt, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
  if (!d.VirtualAddress) {
    return;
  }
  // Minimal IMAGE_COR20_HEADER view: cb(4), MajorRuntimeVersion(2),
  // MinorRuntimeVersion(2). (corhdr.h is not on the Common include path.)
  struct Cor20Mini {
    uint32_t cb;
    uint16_t major;
    uint16_t minor;
  };
  const auto *c = PtrAt<Cor20Mini>(data, RvaToOffset(data, nt, d.VirtualAddress));
  if (!c) {
    return;
  }
  info.isDotNet = true;
  info.dotNetRuntimeVersion =
      std::to_string(c->major) + "." + std::to_string(c->minor);
}

// Debug directory (DataDirectory[6]): count entries; for a CodeView (RSDS)
// record, extract the embedded PDB path (after the 24-byte sig+GUID+age prefix).
void ParseDebug(const std::vector<uint8_t> &data, const IMAGE_NT_HEADERS *nt,
                const OptHeaderView &opt, PeInfo &info) {
  const IMAGE_DATA_DIRECTORY d = DirOf(opt, IMAGE_DIRECTORY_ENTRY_DEBUG);
  if (!d.VirtualAddress || d.Size < sizeof(IMAGE_DEBUG_DIRECTORY)) {
    return;
  }
  const size_t base = RvaToOffset(data, nt, d.VirtualAddress);
  if (!base) {
    return;
  }
  const uint32_t count = std::min<uint32_t>(
      d.Size / static_cast<uint32_t>(sizeof(IMAGE_DEBUG_DIRECTORY)), 64);
  info.debugEntryCount = count;
  for (uint32_t i = 0; i < count; ++i) {
    const auto *dbg = PtrAt<IMAGE_DEBUG_DIRECTORY>(
        data, base + i * sizeof(IMAGE_DEBUG_DIRECTORY));
    if (!dbg) {
      break;
    }
    if (dbg->Type != IMAGE_DEBUG_TYPE_CODEVIEW) {
      continue;
    }
    size_t cvOff = dbg->PointerToRawData;
    if (cvOff == 0 || cvOff >= data.size()) {
      cvOff = RvaToOffset(data, nt, dbg->AddressOfRawData);
    }
    if (cvOff == 0 || cvOff + 24 > data.size()) {
      continue;
    }
    if (std::memcmp(data.data() + cvOff, "RSDS", 4) != 0) {
      continue;
    }
    info.pdbPath = ReadAsciiZ(data, cvOff + 24); // skip CvSig(4)+GUID(16)+Age(4)
    break;
  }
}

// Parse a VS_VERSIONINFO blob's StringFileInfo into the known fields. The node
// tree is { wLength, wValueLength, wType, szKey(UTF-16Z), pad, Value, children },
// 32-bit aligned relative to the blob base. Every length is bounded so a
// malformed resource fails closed rather than looping.
void ParseVersionStrings(const uint8_t *blob, size_t len, PeVersionInfo &vi) {
  auto Align4 = [](size_t x) { return (x + 3) & ~static_cast<size_t>(3); };
  auto ReadKey = [&](size_t pos, size_t limit, size_t &outEnd) {
    std::string s;
    size_t p = pos;
    while (p + 2 <= limit) {
      uint16_t w = 0;
      std::memcpy(&w, blob + p, 2);
      p += 2;
      if (w == 0) {
        break;
      }
      s.push_back(w < 0x80 ? static_cast<char>(w) : '?');
    }
    outEnd = p;
    return s;
  };
  if (len < 6) {
    return;
  }
  uint16_t rootLen = 0;
  std::memcpy(&rootLen, blob, 2);
  if (rootLen == 0 || rootLen > len) {
    rootLen = static_cast<uint16_t>(len);
  }
  uint16_t rootValLen = 0;
  std::memcpy(&rootValLen, blob + 2, 2);
  size_t keyEnd = 0;
  if (ReadKey(6, rootLen, keyEnd) != "VS_VERSION_INFO") {
    return;
  }
  size_t pos = Align4(Align4(keyEnd) + rootValLen); // skip VS_FIXEDFILEINFO value
  while (pos + 6 <= rootLen) {
    uint16_t cLen = 0;
    std::memcpy(&cLen, blob + pos, 2);
    if (cLen == 0) {
      break;
    }
    size_t cEnd = std::min<size_t>(pos + cLen, rootLen);
    size_t cKeyEnd = 0;
    const std::string cKey = ReadKey(pos + 6, cEnd, cKeyEnd);
    if (cKey == "StringFileInfo") {
      size_t st = Align4(cKeyEnd);
      while (st + 6 <= cEnd) {
        uint16_t stLen = 0;
        std::memcpy(&stLen, blob + st, 2);
        if (stLen == 0) {
          break;
        }
        size_t stEnd = std::min<size_t>(st + stLen, cEnd);
        size_t stKeyEnd = 0;
        ReadKey(st + 6, stEnd, stKeyEnd); // lang/codepage key, ignored
        size_t s = Align4(stKeyEnd);
        while (s + 6 <= stEnd) {
          uint16_t sLen = 0;
          std::memcpy(&sLen, blob + s, 2);
          if (sLen == 0) {
            break;
          }
          size_t sEnd = std::min<size_t>(s + sLen, stEnd);
          size_t sKeyEnd = 0;
          const std::string name = ReadKey(s + 6, sEnd, sKeyEnd);
          size_t vEnd = 0;
          const std::string val = ReadKey(Align4(sKeyEnd), sEnd, vEnd);
          vi.present = true;
          if (name == "CompanyName") {
            vi.companyName = val;
          } else if (name == "ProductName") {
            vi.productName = val;
          } else if (name == "FileDescription") {
            vi.fileDescription = val;
          } else if (name == "OriginalFilename") {
            vi.originalFilename = val;
          } else if (name == "InternalName") {
            vi.internalName = val;
          } else if (name == "FileVersion") {
            vi.fileVersion = val;
          } else if (name == "ProductVersion") {
            vi.productVersion = val;
          } else if (name == "LegalCopyright") {
            vi.legalCopyright = val;
          }
          s = Align4(sEnd);
        }
        st = Align4(stEnd);
      }
    }
    pos = Align4(cEnd);
  }
}

// VERSIONINFO (DataDirectory[2] -> RT_VERSION resource): walk the 3-level
// resource tree to the first RT_VERSION data entry, then parse its StringFileInfo.
void ParseVersionInfo(const std::vector<uint8_t> &data, const IMAGE_NT_HEADERS *nt,
                      const OptHeaderView &opt, PeInfo &info) {
  const IMAGE_DATA_DIRECTORY d = DirOf(opt, IMAGE_DIRECTORY_ENTRY_RESOURCE);
  if (!d.VirtualAddress) {
    return;
  }
  const size_t resBase = RvaToOffset(data, nt, d.VirtualAddress);
  const auto *root = PtrAt<IMAGE_RESOURCE_DIRECTORY>(data, resBase);
  if (!root) {
    return;
  }
  const int rootCount = root->NumberOfNamedEntries + root->NumberOfIdEntries;
  const size_t l1Entries = resBase + sizeof(IMAGE_RESOURCE_DIRECTORY);
  size_t verDir = 0;
  for (int i = 0; i < rootCount && i < 256; ++i) {
    const auto *e = PtrAt<IMAGE_RESOURCE_DIRECTORY_ENTRY>(
        data, l1Entries + i * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
    if (!e) {
      break;
    }
    if (!e->NameIsString && e->Id == 16 /*RT_VERSION*/ && e->DataIsDirectory) {
      verDir = resBase + e->OffsetToDirectory;
      break;
    }
  }
  if (!verDir) {
    return;
  }
  const auto *l2 = PtrAt<IMAGE_RESOURCE_DIRECTORY>(data, verDir);
  if (!l2 || (l2->NumberOfNamedEntries + l2->NumberOfIdEntries) <= 0) {
    return;
  }
  const auto *l2e = PtrAt<IMAGE_RESOURCE_DIRECTORY_ENTRY>(
      data, verDir + sizeof(IMAGE_RESOURCE_DIRECTORY));
  if (!l2e || !l2e->DataIsDirectory) {
    return;
  }
  const size_t l3Dir = resBase + l2e->OffsetToDirectory;
  const auto *l3 = PtrAt<IMAGE_RESOURCE_DIRECTORY>(data, l3Dir);
  const auto *l3e = PtrAt<IMAGE_RESOURCE_DIRECTORY_ENTRY>(
      data, l3Dir + sizeof(IMAGE_RESOURCE_DIRECTORY));
  if (!l3 || !l3e || l3e->DataIsDirectory) {
    return;
  }
  const auto *de = PtrAt<IMAGE_RESOURCE_DATA_ENTRY>(data, resBase + l3e->OffsetToData);
  if (!de || de->Size == 0) {
    return;
  }
  const size_t blobOff = RvaToOffset(data, nt, de->OffsetToData);
  if (!blobOff || blobOff >= data.size()) {
    return;
  }
  size_t blobLen = de->Size;
  if (blobOff + blobLen > data.size()) {
    blobLen = data.size() - blobOff;
  }
  ParseVersionStrings(data.data() + blobOff, blobLen, info.versionInfo);
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
  info.isDll = (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
  info.machine = nt->FileHeader.Machine;
  info.numberOfSections = nt->FileHeader.NumberOfSections;
  info.timeDateStamp = nt->FileHeader.TimeDateStamp;
  ParseRichHeader(data, ntOffset, info); // DOS-stub fingerprint, import-independent

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

  // T47 depth: the remaining data directories are parsed regardless of whether
  // the file imports anything (a packed stub or a resource-only DLL may not).
  const OptHeaderView opt = ViewOptHeader(nt);
  const auto certificate = DirOf(opt, IMAGE_DIRECTORY_ENTRY_SECURITY);
  if (info.overlaySize >= 8 && certificate.VirtualAddress == info.overlayOffset &&
      certificate.Size == info.overlaySize && certificate.VirtualAddress < data.size() &&
      certificate.Size <= data.size() - certificate.VirtualAddress) {
    // SECURITY.VirtualAddress is a file offset, unlike other directories.
    const auto* bytes = data.data() + certificate.VirtualAddress;
    uint32_t length = 0; uint16_t revision = 0, kind = 0;
    std::memcpy(&length, bytes, 4); std::memcpy(&revision, bytes + 4, 2); std::memcpy(&kind, bytes + 6, 2);
    info.overlayIsCertificateOnly = length >= 8 && length <= certificate.Size &&
        ((static_cast<uint64_t>(length) + 7) & ~7ull) == certificate.Size && revision == 0x200 && kind == 2;
  }
  ParseExports(data, nt, opt, info);
  ParseTls(data, nt, opt, info);
  ParseDotNet(data, nt, opt, info);
  ParseDebug(data, nt, opt, info);
  ParseVersionInfo(data, nt, opt, info);

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

uint32_t AuthenticodeVerificationStatus(const std::filesystem::path &path) {
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
  return static_cast<uint32_t>(status);
}

bool HasAuthenticodeSignature(const std::filesystem::path &path) {
  return AuthenticodeVerificationStatus(path) == ERROR_SUCCESS;
}

std::string AuthenticodeSignerName(const std::filesystem::path &path) {
  HCERTSTORE store = nullptr;
  HCRYPTMSG msg = nullptr;
  const std::wstring wide = path.wstring();
  // Pull the embedded PKCS#7 signature blob (cert store + signed message).
  if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, wide.c_str(),
                        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                        CERT_QUERY_FORMAT_FLAG_BINARY, 0, nullptr, nullptr,
                        nullptr, &store, &msg, nullptr)) {
    return {};
  }
  // RAII: release the crypto handles on EVERY path out of here, including an
  // exception (e.g. bad_alloc) thrown by the allocations below.
  struct HandleGuard {
    HCERTSTORE &store;
    HCRYPTMSG &msg;
    ~HandleGuard() {
      if (msg) CryptMsgClose(msg);
      if (store) CertCloseStore(store, 0);
    }
  } handleGuard{store, msg};

  std::string result;
  // The signer's cert is identified by (Issuer, SerialNumber); use that to find
  // the leaf cert in the message's store, then read its display name.
  DWORD infoSize = 0;
  if (msg &&
      CryptMsgGetParam(msg, CMSG_SIGNER_CERT_INFO_PARAM, 0, nullptr, &infoSize) &&
      infoSize >= sizeof(CERT_INFO)) {
    std::vector<BYTE> buf(infoSize);
    if (CryptMsgGetParam(msg, CMSG_SIGNER_CERT_INFO_PARAM, 0, buf.data(),
                         &infoSize)) {
      auto *certInfo = reinterpret_cast<CERT_INFO *>(buf.data());
      PCCERT_CONTEXT cert = CertFindCertificateInStore(
          store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
          CERT_FIND_SUBJECT_CERT, certInfo, nullptr);
      if (cert) {
        struct CertGuard {
          PCCERT_CONTEXT c;
          ~CertGuard() {
            if (c) CertFreeCertificateContext(c);
          }
        } certGuard{cert};
        const DWORD n = CertGetNameStringW(
            cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
        if (n > 1) { // n counts the trailing NUL; >1 means at least one char
          std::wstring name(n, L'\0');
          CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr,
                             name.data(), n);
          while (!name.empty() && name.back() == L'\0') name.pop_back();
          result = WideToUtf8(name);
        }
      }
    }
  }

  return result;
}

std::string DetectPackerFromSections(const std::vector<PeSection> &sections) {
  auto lower = [](std::string s) {
    for (char &c : s) {
      if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    }
    return s;
  };
  auto starts = [](const std::string &s, const char *p) {
    return s.rfind(p, 0) == 0;
  };
  for (const auto &sec : sections) {
    const std::string n = lower(sec.name);
    if (starts(n, "upx")) return "UPX";                 // UPX0/UPX1/UPX2/UPX!
    if (n == ".aspack" || n == ".adata") return "ASPack";
    if (starts(n, ".themida") || starts(n, ".winlice")) return "Themida/WinLicense";
    if (starts(n, ".mpress")) return "MPRESS";
    if (n == ".pec" || starts(n, "pec")) return "PECompact";
    if (starts(n, ".nsp") || starts(n, "nsp")) return "NsPack";
    if (starts(n, ".vmp")) return "VMProtect";
    if (n == ".petite") return "Petite";
    if (starts(n, ".enigma")) return "Enigma";
    if (starts(n, ".y0da")) return "yoda Crypter";
    if (n == ".upack" || starts(n, ".by_dwing")) return "Upack";
    if (starts(n, ".rlpack")) return "RLPack";
    if (starts(n, ".gentee")) return "Gentee";
  }
  return "";
}

} // namespace antimal
