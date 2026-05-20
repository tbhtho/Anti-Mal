#include "antimal/hv/VirtualMachine.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstring>
#include <sstream>
#include <stop_token>
#include <string_view>
#include <thread>
#include <utility>

namespace antimal::hv {

namespace {

uint64_t IoAccessSizeMask(uint8_t size) {
  return size == 1 ? 0xFFull : size == 2 ? 0xFFFFull : 0xFFFFFFFFull;
}

constexpr uint64_t kPageSize = 0x1000ull;
constexpr uint64_t kPageMask = 0x000FFFFFFFFFF000ull;
constexpr uint64_t kAssistReserveBytes = 2ull * 1024ull * 1024ull;
constexpr uint64_t kHighScratchBase = 0x100000000ull;
constexpr uint64_t kFirmwareApertureBase = 0xFC000000ull;
constexpr uint64_t kFirmwareApertureSize = 64ull * 1024ull * 1024ull;
constexpr uint64_t kMmioGapStart = 0xFEC00000ull;
constexpr uint64_t kMmioGapEnd = 0xFEF00000ull;
constexpr uint64_t kImageSearchBackBytes = 256ull * 1024ull * 1024ull;

enum class IrqDeliveryBackend {
  Failed,
  IoApic,
  PicFallback,
};

uint16_t ReadLe16(const uint8_t *p) {
  return static_cast<uint16_t>(p[0] | (static_cast<uint16_t>(p[1]) << 8));
}

uint32_t ReadLe32(const uint8_t *p) {
  return static_cast<uint32_t>(p[0]) |
         (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) |
         (static_cast<uint32_t>(p[3]) << 24);
}

bool IsPrintablePathChar(uint8_t c) {
  return c >= 0x20 && c < 0x7Fu;
}

std::string FormatLegacyIrqState(const IoApic &ioApic,
                                 const PcIoDevices &pcIo, uint8_t irq) {
  const uint64_t entry = ioApic.RedirectionEntry(irq);
  const bool masked = (entry & (1ull << 16)) != 0;
  const uint8_t vector = static_cast<uint8_t>(entry & 0xFFu);
  const uint8_t picBase =
      irq < 8 ? pcIo.MasterPicVectorBase() : pcIo.SlavePicVectorBase();
  const uint8_t picMask = irq < 8 ? pcIo.MasterPicMask() : pcIo.SlavePicMask();
  const bool picMasked = (picMask & (1u << (irq < 8 ? irq : irq - 8))) != 0;
  std::ostringstream out;
  out << "irq" << static_cast<int>(irq) << ": ioapicEntry=0x" << std::hex
      << std::uppercase << entry << std::dec
      << " ioapicMasked=" << (masked ? "true" : "false")
      << " ioapicVector=0x" << std::hex << std::uppercase
      << static_cast<int>(vector) << std::dec
      << " picBase=0x" << std::hex << std::uppercase
      << static_cast<int>(picBase) << " picMask=0x"
      << static_cast<int>(picMask) << std::dec
      << " picMasked=" << (picMasked ? "true" : "false");
  return out.str();
}

std::string ExtractCodeViewPath(const uint8_t *bytes, size_t length,
                                size_t offset) {
  if (offset >= length) {
    return {};
  }
  std::string path;
  for (size_t i = offset; i < length && path.size() < 260; ++i) {
    const uint8_t c = bytes[i];
    if (c == 0) {
      break;
    }
    if (!IsPrintablePathChar(c)) {
      return {};
    }
    path.push_back(static_cast<char>(c));
  }
  const auto lower = [&]() {
    std::string out = path;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) {
                     return static_cast<char>(std::tolower(c));
                   });
    return out;
  }();
  if (lower.find(".pdb") == std::string::npos) {
    return {};
  }
  return path;
}

} // namespace

VirtualMachine::VirtualMachine(const std::filesystem::path &firmwarePath,
                               IBlockDevice *ideDisk,
                               VirtualMachineOptions options)
    : host_(std::clamp<uint32_t>(options.processorCount, 1u, 64u), true, true),
      lowRam_(host_, 0, static_cast<size_t>(options.lowRamBytes),
              GuestMemoryProt::ReadWriteExecute),
      firmware_(host_, firmwarePath),
      vcpu_(host_, 0),
      com1_(SerialConsole::kCom1Base),
      com2_(SerialConsole::kCom2Base) {
  vcpu_.SetX86ResetState();
  (void)vcpu_.TrySetStartupSuspended(false);
  for (uint32_t i = 1; i < host_.ProcessorCount(); ++i) {
    auto ap = std::make_unique<Vcpu>(host_, i);
    ap->SetX86ResetState();
    (void)ap->TrySetStartupSuspended(true);
    apVcpus_.push_back(std::move(ap));
  }
  highMappingBytes_ = options.highRamBytes > 0 ? options.highRamBytes
                                               : options.firmwareHighScratchBytes;
  if (highMappingBytes_ > 0) {
    highRam_ = std::make_unique<GuestMemoryRegion>(
        host_, kHighScratchBase, static_cast<size_t>(highMappingBytes_),
        GuestMemoryProt::ReadWriteExecute);
  }
  if (options.lowRamBytes > kAssistReserveBytes + 32ull * 1024ull * 1024ull) {
    pageTableAssistBase_ = options.lowRamBytes - kAssistReserveBytes;
    pageTableAssistNext_ = pageTableAssistBase_;
    pageTableAssistLimit_ = options.lowRamBytes;
  }
  if (firmware_.Gpa() > kFirmwareApertureBase) {
    // Split the scratch region around the IOAPIC/HPET/LAPIC MMIO gap
    // (0xFEC00000-0xFEEFFFFF) so those addresses generate MMIO exits
    // instead of being silently absorbed by RAM.
    const uint64_t fwGpa = firmware_.Gpa();
    if (kMmioGapStart > kFirmwareApertureBase) {
      const auto lowerSize =
          static_cast<size_t>(kMmioGapStart - kFirmwareApertureBase);
      firmwareLowScratch_ = std::make_unique<GuestMemoryRegion>(
          host_, kFirmwareApertureBase, lowerSize,
          GuestMemoryProt::ReadWriteExecute);
      std::memset(firmwareLowScratch_->HostPtr(), 0, lowerSize);
    }
    if (fwGpa > kMmioGapEnd) {
      const auto upperSize = static_cast<size_t>(fwGpa - kMmioGapEnd);
      firmwareUpperScratch_ = std::make_unique<GuestMemoryRegion>(
          host_, kMmioGapEnd, upperSize,
          GuestMemoryProt::ReadWriteExecute);
      std::memset(firmwareUpperScratch_->HostPtr(), 0, upperSize);
    }
  }
  // Map the IOAPIC and HPET MMIO ranges as read-only traps. WHP rejects
  // zero-permission mappings (E_INVALIDARG), but read-only is accepted and
  // causes guest *writes* to these addresses to trigger EPT write-violation
  // exits (WHvRunVpExitReasonMemoryAccess). Guest reads hit the zero-filled
  // host buffer — the MMIO exit handler patches in the correct device-model
  // value before resuming.
  ioApicTrap_ = std::make_unique<GuestMemoryRegion>(
      host_, IoApic::kDefaultMmioBase, kPageSize, GuestMemoryProt::ReadOnly);
  hpetTrap_ = std::make_unique<GuestMemoryRegion>(
      host_, HpetDevice::kDefaultMmioBase, kPageSize, GuestMemoryProt::ReadOnly);

  PcIoMemoryLayout layout{};
  layout.lowRamBytes =
      pageTableAssistBase_ != 0 ? pageTableAssistBase_ : options.lowRamBytes;
  layout.highRamBytes = options.highRamBytes;
  pcIo_.SetMemoryLayout(layout);
  pcIo_.SetProcessorCount(host_.ProcessorCount());
  pcIo_.SetAcpiTablesEnabled(options.enableAcpiTables);
  if (options.enableFramebuffer) {
    framebuffer_ = std::make_unique<GuestMemoryRegion>(
        host_, BochsVbeDevice::kFramebufferGpa,
        BochsVbeDevice::kFramebufferSize, GuestMemoryProt::ReadWrite);
    pcIo_.SetVgaControllerPresent(true);
    vbe_.SetFramebufferHostBytes(framebuffer_->HostPtr(), framebuffer_->Size());
  }
  ioApic_.SetDeliveryCallback(&VirtualMachine::DeliverIoApicVector, this);
  mmioBus_.Attach(&ioApic_);
  mmioBus_.Attach(&hpet_);
  AttachDefaultDevices();
  if (ideDisk) {
    AttachIdeDisk(ideDisk);
  }
}

bool VirtualMachine::DeliverIoApicVector(void *context, uint32_t destination,
                                         uint8_t vector) {
  if (!context) {
    return false;
  }
  auto *self = static_cast<VirtualMachine *>(context);
  if (destination == 0 || destination >= self->host_.ProcessorCount()) {
    return self->vcpu_.TryRequestFixedInterrupt(vector);
  }
  const uint32_t apIndex = destination - 1;
  if (apIndex < self->apVcpus_.size() && self->apVcpus_[apIndex]) {
    return self->apVcpus_[apIndex]->TryRequestFixedInterrupt(vector);
  }
  return false;
}

void VirtualMachine::AttachDefaultDevices() {
  bus_.Attach(&com1_, com1_.BasePort(), com1_.LastPort());
  bus_.Attach(&com2_, com2_.BasePort(), com2_.LastPort());
  bus_.Attach(&pcIo_, 0x00, 0x0F);    // legacy DMA controller
  bus_.Attach(&pcIo_, 0x20, 0x21);    // master PIC
  bus_.Attach(&pcIo_, 0x40, 0x43);    // PIT
  bus_.Attach(&ps2_, Ps2Controller::kDataPort, Ps2Controller::kDataPort);
  bus_.Attach(&ps2_, Ps2Controller::kStatusCommandPort,
              Ps2Controller::kStatusCommandPort);
  bus_.Attach(&pcIo_, 0x70, 0x71);    // CMOS/RTC
  bus_.Attach(&pcIo_, 0x80, 0x80);    // POST/delay port
  bus_.Attach(&pcIo_, 0x92, 0x92);    // A20/system control port
  bus_.Attach(&pcIo_, 0xA0, 0xA1);    // slave PIC
  bus_.Attach(&pcIo_, 0x3C0, 0x3DF);  // legacy VGA palette/status ports
  bus_.Attach(&pcIo_, 0x402, 0x402);  // OVMF DEBUG_ON_SERIAL_PORT debugcon
  bus_.Attach(&pcIo_, 0xED, 0xED);    // firmware delay port
  bus_.Attach(&pcIo_, 0x510, 0x511);  // QEMU fw_cfg selector/data
  bus_.Attach(&pcIo_, 0xAF00, 0xAF1F); // PIIX4/QEMU CPU hotplug block
  bus_.Attach(&pcIo_, 0xCF8, 0xCFF);  // PCI config mechanism #1
  bus_.Attach(&pcIo_, 0xB000, 0xB0FF); // PIIX4 ACPI PM IO
  if (framebuffer_) {
    bus_.Attach(&vbe_, BochsVbeDevice::kIndexPort,
                BochsVbeDevice::kDataPortAligned);
  }
}

void VirtualMachine::AttachIdeDisk(IBlockDevice *disk) {
  pcIo_.SetIdeControllerPresent(true);
  ide_ = std::make_unique<IdeController>(disk);
  secondaryIde_ = std::make_unique<IdeController>(
      nullptr, IdeController::kSecondaryBase, IdeController::kSecondaryControl);
  bus_.Attach(ide_.get(), IdeController::kPrimaryBase,
              IdeController::kPrimaryLast);
  bus_.Attach(ide_.get(), IdeController::kPrimaryControl,
              IdeController::kPrimaryControl);
  bus_.Attach(secondaryIde_.get(), IdeController::kSecondaryBase,
              IdeController::kSecondaryLast);
  bus_.Attach(secondaryIde_.get(), IdeController::kSecondaryControl,
              IdeController::kSecondaryControl);
}

uint8_t *VirtualMachine::HostPointerForGpa(uint64_t gpa,
                                           size_t length) noexcept {
  auto inRegion = [&](GuestMemoryRegion &region) -> uint8_t * {
    if (gpa < region.Gpa()) {
      return nullptr;
    }
    const uint64_t offset = gpa - region.Gpa();
    if (offset > region.Size() || length > region.Size() - offset) {
      return nullptr;
    }
    return region.HostPtr() + static_cast<size_t>(offset);
  };

  if (auto *ptr = inRegion(lowRam_)) {
    return ptr;
  }
  if (highRam_) {
    if (auto *ptr = inRegion(*highRam_)) {
      return ptr;
    }
  }
  if (firmwareLowScratch_) {
    if (auto *ptr = inRegion(*firmwareLowScratch_)) {
      return ptr;
    }
  }
  if (firmwareUpperScratch_) {
    if (auto *ptr = inRegion(*firmwareUpperScratch_)) {
      return ptr;
    }
  }
  if (framebuffer_) {
    if (auto *ptr = inRegion(*framebuffer_)) {
      return ptr;
    }
  }
  if (firmware_.ContainsGpa(gpa)) {
    const uint64_t offset = gpa - firmware_.Gpa();
    if (offset <= firmware_.Size() && length <= firmware_.Size() - offset) {
      return const_cast<uint8_t *>(firmware_.HostBytes() +
                                   static_cast<size_t>(offset));
    }
  }
  return nullptr;
}

bool VirtualMachine::ReadGuestMemory(uint64_t gva, void *buffer,
                                     size_t length) {
  return ReadGuestMemoryFor(vcpu_, gva, buffer, length);
}

bool VirtualMachine::ReadGuestMemoryFor(Vcpu &vcpu, uint64_t gva, void *buffer,
                                        size_t length) {
  auto *out = static_cast<uint8_t *>(buffer);
  size_t copied = 0;
  while (copied < length) {
    const uint64_t currentGva = gva + copied;
    uint64_t gpa = 0;
    if (!vcpu.TryTranslateGva(currentGva, false, &gpa)) {
      return false;
    }
    const size_t pageLeft =
        static_cast<size_t>(0x1000u - (gpa & 0xFFFu));
    const size_t chunk = std::min(length - copied, pageLeft);
    auto *src = HostPointerForGpa(gpa, chunk);
    if (!src) {
      return false;
    }
    std::memcpy(out + copied, src, chunk);
    copied += chunk;
  }
  return true;
}

bool VirtualMachine::WriteGuestMemory(uint64_t gva, const void *buffer,
                                      size_t length) {
  const auto *in = static_cast<const uint8_t *>(buffer);
  size_t copied = 0;
  while (copied < length) {
    const uint64_t currentGva = gva + copied;
    uint64_t gpa = 0;
    if (!vcpu_.TryTranslateGva(currentGva, true, &gpa)) {
      return false;
    }
    const size_t pageLeft =
        static_cast<size_t>(0x1000u - (gpa & 0xFFFu));
    const size_t chunk = std::min(length - copied, pageLeft);
    auto *dst = HostPointerForGpa(gpa, chunk);
    if (!dst) {
      return false;
    }
    std::memcpy(dst, in + copied, chunk);
    copied += chunk;
  }
  return true;
}

bool VirtualMachine::IdentifyGuestImage(uint64_t gva, VmGuestImageInfo *info) {
  if (!info || gva == 0 || gva == UINT64_MAX || (gva >> 48) != 0) {
    return false;
  }

  auto readCodeViewPath = [&](uint64_t base, uint32_t sizeOfImage,
                              uint32_t debugRva,
                              uint32_t debugSize) -> std::string {
    if (debugRva != 0 && debugSize >= 28 &&
        debugRva < sizeOfImage && debugSize <= sizeOfImage - debugRva) {
      const uint32_t entryCount = std::min<uint32_t>(debugSize / 28, 32);
      std::array<uint8_t, 28> dir{};
      for (uint32_t i = 0; i < entryCount; ++i) {
        if (!ReadGuestMemory(base + debugRva + static_cast<uint64_t>(i) * 28,
                             dir.data(), dir.size())) {
          continue;
        }
        const uint32_t type = ReadLe32(dir.data() + 12);
        const uint32_t sizeOfData = ReadLe32(dir.data() + 16);
        const uint32_t addressOfRawData = ReadLe32(dir.data() + 20);
        if (type != 2 || sizeOfData < 16 || sizeOfData > 4096 ||
            addressOfRawData >= sizeOfImage ||
            sizeOfData > sizeOfImage - addressOfRawData) {
          continue;
        }
        std::vector<uint8_t> cv(sizeOfData);
        if (!ReadGuestMemory(base + addressOfRawData, cv.data(), cv.size())) {
          continue;
        }
        if (cv.size() >= 24 &&
            std::memcmp(cv.data(), "RSDS", 4) == 0) {
          if (auto path = ExtractCodeViewPath(cv.data(), cv.size(), 24);
              !path.empty()) {
            return path;
          }
        }
        if (cv.size() >= 16 &&
            std::memcmp(cv.data(), "NB10", 4) == 0) {
          if (auto path = ExtractCodeViewPath(cv.data(), cv.size(), 16);
              !path.empty()) {
            return path;
          }
        }
      }
    }

    const uint64_t scanBytes =
        std::min<uint64_t>(sizeOfImage, 8ull * 1024ull * 1024ull);
    std::array<uint8_t, 4096> page{};
    for (uint64_t offset = 0; offset < scanBytes; offset += page.size()) {
      const size_t chunk = static_cast<size_t>(
          std::min<uint64_t>(page.size(), scanBytes - offset));
      if (!ReadGuestMemory(base + offset, page.data(), chunk)) {
        continue;
      }
      for (size_t i = 0; i + 24 < chunk; ++i) {
        if (std::memcmp(page.data() + i, "RSDS", 4) == 0) {
          if (auto path = ExtractCodeViewPath(page.data() + i, chunk - i, 24);
              !path.empty()) {
            return path;
          }
        }
        if (i + 16 < chunk && std::memcmp(page.data() + i, "NB10", 4) == 0) {
          if (auto path = ExtractCodeViewPath(page.data() + i, chunk - i, 16);
              !path.empty()) {
            return path;
          }
        }
      }
    }
    return {};
  };

  const uint64_t start = gva & ~(kPageSize - 1);
  const uint64_t limit =
      start > kImageSearchBackBytes ? start - kImageSearchBackBytes : 0;
  auto tryCandidate = [&](uint64_t base) -> bool {
    std::array<uint8_t, 0x400> hdr{};
    if (!ReadGuestMemory(base, hdr.data(), 0x40) ||
        hdr[0] != 'M' || hdr[1] != 'Z') {
      return false;
    }
    const uint32_t peOffset = ReadLe32(hdr.data() + 0x3C);
    if (peOffset < 0x40 || peOffset > 0x1000 ||
        !ReadGuestMemory(base + peOffset, hdr.data(), hdr.size()) ||
        std::memcmp(hdr.data(), "PE\0\0", 4) != 0) {
      return false;
    }
    const uint16_t machine = ReadLe16(hdr.data() + 4);
    const uint16_t sectionCount = ReadLe16(hdr.data() + 6);
    const uint32_t timeDateStamp = ReadLe32(hdr.data() + 8);
    const uint16_t optionalSize = ReadLe16(hdr.data() + 20);
    const uint8_t *optional = hdr.data() + 24;
    if (sectionCount == 0 || sectionCount >= 128 || optionalSize < 96 ||
        24u + optionalSize > hdr.size()) {
      return false;
    }
    const uint16_t magic = ReadLe16(optional);
    const bool pe32Plus = magic == 0x20Bu;
    const bool pe32 = magic == 0x10Bu;
    if (!pe32 && !pe32Plus) {
      return false;
    }
    const uint32_t entryPointRva = ReadLe32(optional + 16);
    const uint32_t sizeOfImage = ReadLe32(optional + 56);
    const uint16_t subsystem = ReadLe16(optional + 68);
    const uint32_t dataDirectoryBase = pe32Plus ? 112 : 96;
    const uint32_t numberOfRvaAndSizes =
        optionalSize >= dataDirectoryBase
            ? ReadLe32(optional + dataDirectoryBase - 4)
            : 0;
    uint32_t debugRva = 0;
    uint32_t debugSize = 0;
    if (numberOfRvaAndSizes > 6 &&
        optionalSize >= dataDirectoryBase + 7 * 8) {
      debugRva = ReadLe32(optional + dataDirectoryBase + 6 * 8);
      debugSize = ReadLe32(optional + dataDirectoryBase + 6 * 8 + 4);
    }
    if (sizeOfImage < 0x1000 || sizeOfImage > 512u * 1024u * 1024u ||
        gva < base || gva >= base + sizeOfImage) {
      return false;
    }

    VmGuestImageInfo found{};
    found.valid = true;
    found.base = base;
    found.sizeOfImage = sizeOfImage;
    found.entryPointRva = entryPointRva;
    found.timeDateStamp = timeDateStamp;
    found.machine = machine;
    found.subsystem = subsystem;
    found.pdbPath = readCodeViewPath(base, sizeOfImage, debugRva, debugSize);
    *info = std::move(found);
    return true;
  };

  std::array<uint8_t, 4096> page{};
  for (uint64_t pageBase = start;; pageBase -= kPageSize) {
    if (ReadGuestMemory(pageBase, page.data(), page.size())) {
      for (size_t offset = 0; offset + 0x40 <= page.size(); offset += 0x10) {
        if (page[offset] == 'M' && page[offset + 1] == 'Z' &&
            tryCandidate(pageBase + offset)) {
          return true;
        }
      }
    }
    if (pageBase == 0 || pageBase <= limit) {
      break;
    }
  }
  return false;
}

uint64_t VirtualMachine::AllocatePageTableAssistPage() {
  if (pageTableAssistNext_ == 0 ||
      pageTableAssistNext_ + kPageSize > pageTableAssistLimit_) {
    return 0;
  }
  auto *page = HostPointerForGpa(pageTableAssistNext_, kPageSize);
  if (!page) {
    return 0;
  }
  std::memset(page, 0, static_cast<size_t>(kPageSize));
  const uint64_t gpa = pageTableAssistNext_;
  pageTableAssistNext_ += kPageSize;
  return gpa;
}

bool VirtualMachine::TryAssistFirmwarePageFault(uint64_t gva,
                                                uint32_t errorCode,
                                                uint64_t *mappedGpa) {
  constexpr uint64_t kPresent = 1ull;
  constexpr uint64_t kWritable = 1ull << 1;
  constexpr uint64_t kPageSizeFlag = 1ull << 7;

  const bool writeFault = (errorCode & 0x2u) != 0;
  if (!writeFault || gva < kHighScratchBase ||
      gva >= kHighScratchBase + kFirmwareApertureSize) {
    return false;
  }
  if (mappedGpa) {
    *mappedGpa = 0;
  }

  auto readEntry = [&](uint64_t gpa, uint64_t *value) {
    auto *ptr = HostPointerForGpa(gpa, sizeof(uint64_t));
    if (!ptr) {
      return false;
    }
    std::memcpy(value, ptr, sizeof(*value));
    return true;
  };
  auto writeEntry = [&](uint64_t gpa, uint64_t value) {
    auto *ptr = HostPointerForGpa(gpa, sizeof(uint64_t));
    if (!ptr) {
      return false;
    }
    std::memcpy(ptr, &value, sizeof(value));
    return true;
  };

  const auto diag = vcpu_.ReadDiagState();
  const uint64_t pml4Base = diag.cr3 & kPageMask;
  const uint64_t pml4Index = (gva >> 39) & 0x1FFull;
  const uint64_t pdptIndex = (gva >> 30) & 0x1FFull;
  const uint64_t pdIndex = (gva >> 21) & 0x1FFull;
  const uint64_t ptIndex = (gva >> 12) & 0x1FFull;

  uint64_t pml4e = 0;
  if (!readEntry(pml4Base + pml4Index * sizeof(uint64_t), &pml4e) ||
      (pml4e & kPresent) == 0) {
    return false;
  }

  const uint64_t pdptBase = pml4e & kPageMask;
  const uint64_t pdpteGpa = pdptBase + pdptIndex * sizeof(uint64_t);
  uint64_t pdpte = 0;
  if (!readEntry(pdpteGpa, &pdpte)) {
    return false;
  }
  if ((pdpte & kPresent) == 0) {
    const uint64_t pdBase = AllocatePageTableAssistPage();
    if (pdBase == 0) {
      return false;
    }
    pdpte = pdBase | kPresent | kWritable;
    if (!writeEntry(pdpteGpa, pdpte)) {
      return false;
    }
  }
  if ((pdpte & kPageSizeFlag) != 0) {
    if (mappedGpa) {
      *mappedGpa = (pdpte & 0x000FFFFFC0000000ull) |
                   (gva & 0x3FFFFFFFull);
    }
    return true;
  }

  const uint64_t pdBase = pdpte & kPageMask;
  const uint64_t pdeGpa = pdBase + pdIndex * sizeof(uint64_t);
  uint64_t pde = 0;
  if (!readEntry(pdeGpa, &pde)) {
    return false;
  }
  if ((pde & kPresent) == 0) {
    const uint64_t offset2m =
        (gva - kHighScratchBase) & 0xFFFFFFFFFFE00000ull;
    const uint64_t page2m = kHighScratchBase + offset2m;
    if (mappedGpa) {
      *mappedGpa = page2m | (gva & 0x1FFFFFull);
    }
    return writeEntry(pdeGpa, page2m | kPresent | kWritable | kPageSizeFlag);
  }
  if ((pde & kPageSizeFlag) != 0) {
    if (mappedGpa) {
      *mappedGpa = (pde & 0x000FFFFFFFE00000ull) | (gva & 0x1FFFFFull);
    }
    return true;
  }

  const uint64_t ptBase = pde & kPageMask;
  const uint64_t pteGpa = ptBase + ptIndex * sizeof(uint64_t);
  uint64_t pte = 0;
  if (!readEntry(pteGpa, &pte)) {
    return false;
  }
  if ((pte & kPresent) != 0) {
    if (mappedGpa) {
      *mappedGpa = (pte & kPageMask) | (gva & 0xFFFull);
    }
    return true;
  }
  const uint64_t page4k =
      kHighScratchBase + ((gva - kHighScratchBase) & 0xFFFFFFFFFFFFF000ull);
  if (mappedGpa) {
    *mappedGpa = page4k | (gva & 0xFFFull);
  }
  return writeEntry(pteGpa, page4k | kPresent | kWritable);
}

bool VirtualMachine::HandleStringIoPortAccess(
    const WHV_X64_IO_PORT_ACCESS_CONTEXT &io, uint64_t rflags,
    bool *allPortsHandled) {
  if (!allPortsHandled) {
    return false;
  }
  *allPortsHandled = true;

  const uint8_t size = static_cast<uint8_t>(io.AccessInfo.AccessSize);
  if (size != 1 && size != 2 && size != 4) {
    return false;
  }

  const uint64_t count = io.AccessInfo.RepPrefix ? io.Rcx : 1;
  if (count > 0x100000ull) {
    return false;
  }

  uint64_t rcx = io.Rcx;
  uint64_t rsi = io.Rsi;
  uint64_t rdi = io.Rdi;
  const bool decrement = (rflags & (1ull << 10)) != 0;
  const auto advance = [&]() -> uint64_t {
    return decrement ? (0ull - static_cast<uint64_t>(size))
                     : static_cast<uint64_t>(size);
  };

  for (uint64_t i = 0; i < count; ++i) {
    if (io.AccessInfo.IsWrite) {
      uint8_t bytes[4]{};
      const uint64_t gva = io.Ds.Base + rsi;
      if (!ReadGuestMemory(gva, bytes, size)) {
        return false;
      }
      uint32_t value = 0;
      for (uint8_t b = 0; b < size; ++b) {
        value |= static_cast<uint32_t>(bytes[b]) << (b * 8);
      }
      if (!bus_.Write(io.PortNumber, value, size)) {
        *allPortsHandled = false;
      }
      rsi += advance();
    } else {
      uint32_t value = 0;
      if (!bus_.Read(io.PortNumber, size, &value)) {
        *allPortsHandled = false;
      }
      uint8_t bytes[4]{};
      for (uint8_t b = 0; b < size; ++b) {
        bytes[b] = static_cast<uint8_t>((value >> (b * 8)) & 0xFFu);
      }
      const uint64_t gva = io.Es.Base + rdi;
      if (!WriteGuestMemory(gva, bytes, size)) {
        return false;
      }
      rdi += advance();
    }
  }

  if (io.AccessInfo.RepPrefix) {
    rcx = 0;
  }
  vcpu_.WriteRcxRsiRdi(rcx, rsi, rdi);
  return true;
}

VmRunSummary VirtualMachine::BootForSteps(int maxSteps) {
  return RunLoop(maxSteps, std::chrono::steady_clock::time_point::max());
}

VmRunSummary VirtualMachine::Run(const VmRunRequest &request) {
  const auto timeout = request.timeout.count() > 0
                           ? request.timeout
                           : std::chrono::milliseconds{1};
  auto summary = RunLoop(request.maxSteps,
                         std::chrono::steady_clock::now() + timeout,
                         request.progressCallback, request.progressInterval,
                         request.cancelRequested);
  summary.networkMode = request.networkMode;
  return summary;
}

VmRunSummary VirtualMachine::RunLoop(
    int maxSteps, std::chrono::steady_clock::time_point deadline,
    const VmProgressCallback &progressCallback,
    std::chrono::milliseconds progressInterval,
    std::shared_ptr<std::atomic_bool> cancelRequested) {
  VmRunSummary summary;
  summary.started = true;
  summary.processorCount = host_.ProcessorCount();
  // Steps with no I/O progress before we call the guest stuck. Sized loosely
  // so a long stretch of PCI scan + ACPI probe (~20K exits) does not get
  // mis-flagged when the guest is just busy.
  constexpr int kStuckStepLimit = 250000;
  // Timer interrupt cadence + watchdog cancellation tick in milliseconds.
  // The watchdog services both jobs: cancel a vCPU run if it stays inside
  // WHvRunVirtualProcessor too long, and inject the APIC LVT timer vector
  // periodically so a Windows scheduler sees timer ticks.
  using namespace std::chrono_literals;
  constexpr auto kTimerInterval = 10ms;
  constexpr auto kWatchdogCancelAfter = 750ms;

  std::atomic<bool> inRun{false};
  std::atomic<int> watchdogCancels{0};
  std::atomic<int> timerRequested{0};
  std::atomic<int> timerInjected{0};
  std::atomic<bool> stopAps{false};
  std::atomic<uint64_t> apVcpuExits{0};
  std::atomic<uint64_t> apHltExits{0};
  std::atomic<uint64_t> apCpuidExits{0};
  std::atomic<uint64_t> apUnhandledExits{0};

  std::vector<std::jthread> apThreads;
  apThreads.reserve(apVcpus_.size());
  auto injectLapicTimer = [&](Vcpu &cpu) {
    uint32_t lvt = 0;
    if (cpu.TryReadApicLvtTimer(&lvt) && (lvt & (1u << 16)) == 0) {
      const uint8_t vector = static_cast<uint8_t>(lvt & 0xFFu);
      if (vector >= 0x10) {
        timerRequested.fetch_add(1, std::memory_order_relaxed);
        if (cpu.TryRequestFixedInterrupt(vector)) {
          timerInjected.fetch_add(1, std::memory_order_relaxed);
        }
      }
    }
  };
  for (auto &ap : apVcpus_) {
    auto *cpu = ap.get();
    apThreads.emplace_back([&, cpu](std::stop_token stop) {
      while (!stop.stop_requested() && !stopAps.load(std::memory_order_relaxed)) {
        try {
          const auto reason = cpu->Run();
          apVcpuExits.fetch_add(1, std::memory_order_relaxed);
          if (stop.stop_requested() ||
              stopAps.load(std::memory_order_relaxed)) {
            break;
          }
          const auto &ctx = cpu->LastExit();
          const uint64_t instrLen = ctx.VpContext.InstructionLength;
          switch (reason) {
          case WHvRunVpExitReasonX64Cpuid:
            apCpuidExits.fetch_add(1, std::memory_order_relaxed);
            cpu->EmulateCpuidExit();
            break;
          case WHvRunVpExitReasonX64Halt:
            apHltExits.fetch_add(1, std::memory_order_relaxed);
            cpu->AdvanceRip(instrLen > 0 ? instrLen : 1);
            injectLapicTimer(*cpu);
            std::this_thread::sleep_for(1ms);
            break;
          case WHvRunVpExitReasonCanceled:
            break;
          case WHvRunVpExitReasonMemoryAccess:
            apUnhandledExits.fetch_add(1, std::memory_order_relaxed);
            if (instrLen > 0) {
              cpu->AdvanceRip(instrLen);
            } else {
              return;
            }
            break;
          case WHvRunVpExitReasonX64IoPortAccess:
            apUnhandledExits.fetch_add(1, std::memory_order_relaxed);
            if (instrLen > 0) {
              cpu->AdvanceRip(instrLen);
            } else {
              return;
            }
            break;
          default:
            apUnhandledExits.fetch_add(1, std::memory_order_relaxed);
            return;
          }
        } catch (...) {
          apUnhandledExits.fetch_add(1, std::memory_order_relaxed);
          return;
        }
      }
    });
  }

  auto stopApWorkers = [&]() {
    stopAps.store(true, std::memory_order_relaxed);
    for (auto &ap : apVcpus_) {
      if (ap) {
        ap->CancelRun();
      }
    }
    for (auto &thread : apThreads) {
      thread.request_stop();
    }
    for (auto &thread : apThreads) {
      if (thread.joinable()) {
        thread.join();
      }
    }
  };

  std::jthread watchdog([&](std::stop_token stop) {
    auto lastTimer = std::chrono::steady_clock::now();
    auto runEntered = std::chrono::steady_clock::now();
    bool wasInRun = false;
    while (!stop.stop_requested()) {
      std::this_thread::sleep_for(kTimerInterval);
      const auto now = std::chrono::steady_clock::now();
      const bool runningNow = inRun.load(std::memory_order_relaxed);
      if (runningNow && !wasInRun) {
        runEntered = now;
      }
      wasInRun = runningNow;

      if (now - lastTimer >= kTimerInterval) {
        injectLapicTimer(vcpu_);
        for (auto &ap : apVcpus_) {
          if (ap) {
            injectLapicTimer(*ap);
          }
        }
        lastTimer = now;
      }

      if (runningNow && now - runEntered >= kWatchdogCancelAfter) {
        vcpu_.CancelRun();
        watchdogCancels.fetch_add(1, std::memory_order_relaxed);
        runEntered = now;
      }
    }
  });

  uint64_t lastCanceledRip = 0;
  int sameCanceledRipStreak = 0;
  int stepsSinceProgress = 0;
  uint64_t lastIdeCommands = 0;
  const auto runStarted = std::chrono::steady_clock::now();
  auto lastProgressFire = runStarted;

  // Per-BSP RIP-at-exit ring + 16-byte-bucket hotspot histogram. Both are
  // free observability: we already have the exit context in hand, no extra
  // hypercalls. The ring captures temporal order (useful when a sample is
  // wedged in a 2-3 instruction loop); the histogram captures distribution
  // across the whole run.
  constexpr size_t kRipRingSize = 64;
  std::array<uint64_t, kRipRingSize> ripRing{};
  size_t ripRingHead = 0;
  size_t ripRingCount = 0;
  std::map<uint64_t, uint64_t> ripHotspots;
  auto captureFatalState = [&]() {
    try {
      const auto state = vcpu_.ReadDiagState();
      summary.fatalRip = state.rip;
      summary.fatalCsSelector = state.cs_selector;
      summary.fatalRipBytesValid =
          ReadGuestMemory(summary.fatalRip, summary.fatalRipBytes,
                          sizeof(summary.fatalRipBytes));
      summary.fatalRipWindowBase =
          summary.fatalRip >= 32 ? summary.fatalRip - 32 : summary.fatalRip;
      summary.fatalRipWindowValid =
          ReadGuestMemory(summary.fatalRipWindowBase, summary.fatalRipWindow,
                          sizeof(summary.fatalRipWindow));
      (void)IdentifyGuestImage(summary.fatalRip, &summary.fatalRipImage);
      const WHV_REGISTER_NAME names[] = {
          WHvX64RegisterRax, WHvX64RegisterRbx, WHvX64RegisterRcx,
          WHvX64RegisterRdx, WHvX64RegisterRsi, WHvX64RegisterRdi,
          WHvX64RegisterRbp, WHvX64RegisterRsp, WHvX64RegisterR8,
          WHvX64RegisterR9,  WHvX64RegisterR10, WHvX64RegisterR11,
          WHvX64RegisterR12, WHvX64RegisterR13, WHvX64RegisterR14,
          WHvX64RegisterR15};
      WHV_REGISTER_VALUE values[16]{};
      if (SUCCEEDED(WHvGetVirtualProcessorRegisters(
              vcpu_.Partition(), vcpu_.Index(), names,
              static_cast<UINT32>(sizeof(names) / sizeof(names[0])), values))) {
        summary.fatalRax = values[0].Reg64;
        summary.fatalRbx = values[1].Reg64;
        summary.fatalRcx = values[2].Reg64;
        summary.fatalRdx = values[3].Reg64;
        summary.fatalRsi = values[4].Reg64;
        summary.fatalRdi = values[5].Reg64;
        summary.fatalRbp = values[6].Reg64;
        summary.fatalRsp = values[7].Reg64;
        summary.fatalR8 = values[8].Reg64;
        summary.fatalR9 = values[9].Reg64;
        summary.fatalR10 = values[10].Reg64;
        summary.fatalR11 = values[11].Reg64;
        summary.fatalR12 = values[12].Reg64;
        summary.fatalR13 = values[13].Reg64;
        summary.fatalR14 = values[14].Reg64;
        summary.fatalR15 = values[15].Reg64;
        summary.fatalRdxBytesValid =
            ReadGuestMemory(summary.fatalRdx, summary.fatalRdxBytes,
                            sizeof(summary.fatalRdxBytes));
        summary.fatalRsiBytesValid =
            ReadGuestMemory(summary.fatalRsi, summary.fatalRsiBytes,
                            sizeof(summary.fatalRsiBytes));
        summary.fatalRdiBytesValid =
            ReadGuestMemory(summary.fatalRdi, summary.fatalRdiBytes,
                            sizeof(summary.fatalRdiBytes));
        summary.fatalRspBytesValid =
            ReadGuestMemory(summary.fatalRsp, summary.fatalRspBytes,
                            sizeof(summary.fatalRspBytes));
        if (summary.fatalRspBytesValid) {
          for (size_t slot = 0; slot < 4; ++slot) {
            uint64_t address = 0;
            std::memcpy(&address,
                        summary.fatalRspBytes + slot * sizeof(uint64_t),
                        sizeof(address));
            summary.fatalStackReturn[slot] = address;
            if (address == 0 || address == UINT64_MAX ||
                (address >> 48) != 0) {
              continue;
            }
            const uint64_t base = address >= 16 ? address - 16 : address;
            summary.fatalStackReturnWindowBase[slot] = base;
            summary.fatalStackReturnBytesValid[slot] =
                ReadGuestMemory(base, summary.fatalStackReturnBytes[slot],
                                sizeof(summary.fatalStackReturnBytes[slot]));
            (void)IdentifyGuestImage(address,
                                     &summary.fatalStackReturnImage[slot]);
          }
        }
      }
    } catch (...) {
      summary.fatalRip = vcpu_.LastExit().VpContext.Rip;
      summary.fatalCsSelector = vcpu_.LastExit().VpContext.Cs.Selector;
    }
  };
  for (int step = 0; step < maxSteps && !summary.fatal && !summary.idleLoop &&
       !summary.halted && !summary.timedOut && !summary.guestShutdown &&
       !summary.hostStopRequested; ++step) {
    if (std::chrono::steady_clock::now() >= deadline) {
      summary.timedOut = true;
      break;
    }
    if (pcIo_.ShutdownRequested()) {
      summary.guestShutdown = true;
      summary.guestShutdownSleepType = pcIo_.LastSleepType();
      summary.pm1SleepEnable = pcIo_.LastPm1SleepEnable();
      summary.pm1SleepType = pcIo_.LastSleepType();
      summary.pm1ControlValue = pcIo_.LastPm1ControlValue();
      summary.pm1HostStopRequested = pcIo_.LastPm1HostStopRequested();
      summary.pm1SleepRequests = pcIo_.Pm1SleepRequestCount();
      summary.halted = true;
      break;
    }
    inRun.store(true, std::memory_order_relaxed);
    const auto reason = vcpu_.Run();
    inRun.store(false, std::memory_order_relaxed);
    summary.steps = step + 1;
    summary.exitHistogram[static_cast<int>(reason)]++;

    const auto &ctx = vcpu_.LastExit();
    const uint64_t instrLen = ctx.VpContext.InstructionLength;

    // Record this exit's RIP into the ring + hotspot histogram. Skip the
    // synthetic 0 RIP that WHP may report on the very first cancellation
    // before the vCPU has ever entered the guest.
    const uint64_t exitRip = ctx.VpContext.Rip;
    if (exitRip != 0) {
      ripRing[ripRingHead] = exitRip;
      ripRingHead = (ripRingHead + 1) % ripRing.size();
      if (ripRingCount < ripRing.size()) {
        ++ripRingCount;
      }
      // Bucket by 16-byte alignment so adjacent RIPs in the same instruction
      // sequence accumulate together. 16 is a reasonable compromise: tighter
      // than a 64-byte cache line (so we don't merge unrelated loops) and
      // wider than an avg x86 instruction (so a 3-instruction loop coalesces
      // into 1-2 buckets).
      ++ripHotspots[exitRip & ~uint64_t{0xF}];
    }

    // Track I/O progress so we can detect a true wedge (no IO + no IDE work).
    bool madeProgress = false;

    switch (reason) {
    case WHvRunVpExitReasonX64Halt: {
      ++summary.totalHlts;
      vcpu_.AdvanceRip(instrLen > 0 ? instrLen : 1);
      injectLapicTimer(vcpu_);
      break;
    }
    case WHvRunVpExitReasonX64IoPortAccess: {
      madeProgress = true;
      const auto &io = ctx.IoPortAccess;
      const uint16_t port = io.PortNumber;
      const uint8_t size = static_cast<uint8_t>(io.AccessInfo.AccessSize);
      summary.ioPortHistogram[port]++;
      if (io.AccessInfo.StringOp) {
        bool allPortsHandled = true;
        if (!HandleStringIoPortAccess(io, ctx.VpContext.Rflags,
                                      &allPortsHandled)) {
          ++summary.unhandledIo;
          summary.fatal = true;
          summary.fatalReason = reason;
          captureFatalState();
          break;
        }
        if (!allPortsHandled) {
          ++summary.unhandledIo;
        }
      } else if (io.AccessInfo.IsWrite) {
        const bool handled =
            bus_.Write(port, static_cast<uint32_t>(io.Rax), size);
        if (!handled) {
          ++summary.unhandledIo;
        }
      } else {
        uint32_t value = 0;
        const bool handled = bus_.Read(port, size, &value);
        if (!handled) {
          ++summary.unhandledIo;
        }
        const uint64_t mask = IoAccessSizeMask(size);
        vcpu_.WriteRax((io.Rax & ~mask) | (static_cast<uint64_t>(value) & mask));
      }
      vcpu_.AdvanceRip(instrLen != 0 ? instrLen : io.InstructionByteCount);
      break;
    }
    case WHvRunVpExitReasonX64Cpuid:
      madeProgress = true;
      summary.cpuidLeafHistogram[
          static_cast<uint32_t>(ctx.CpuidAccess.Rax)]++;
      vcpu_.EmulateCpuidExit();
      break;
    case WHvRunVpExitReasonException: {
      const auto &ex = ctx.VpException;
      summary.lastExceptionType = ex.ExceptionType;
      summary.lastExceptionErrorCode = ex.ErrorCode;
      summary.lastExceptionParameter = ex.ExceptionParameter;
      uint64_t assistedGpa = 0;
      if (ex.ExceptionType == WHvX64ExceptionTypePageFault &&
          TryAssistFirmwarePageFault(ex.ExceptionParameter, ex.ErrorCode,
                                     &assistedGpa)) {
        ++summary.pageFaultAssists;
        summary.lastPageFaultAssistGva = ex.ExceptionParameter;
        summary.lastPageFaultAssistGpa = assistedGpa;
        madeProgress = true;
        break;
      }
      ++summary.unhandledOther;
      summary.fatal = true;
      summary.fatalReason = reason;
      captureFatalState();
      break;
    }
    case WHvRunVpExitReasonMemoryAccess: {
      const auto &mem = ctx.MemoryAccess;
      const uint64_t gpa = mem.Gpa;
      summary.lastUnhandledMmioGpa = gpa;
      summary.lastUnhandledMmioGva = mem.Gva;
      summary.lastUnhandledMmioAccess = mem.AccessInfo.AccessType;
      summary.lastUnhandledMmioInstructionLength = mem.InstructionByteCount;
      auto *device = mmioBus_.Find(gpa);
      if (device) {
        bool deviceOwned = false;
        const bool emulated =
            mmioEmulator_.TryEmulate(vcpu_, ctx, mmioBus_, &deviceOwned);
        if (emulated) {
          madeProgress = true;
          if (mem.AccessInfo.AccessType == 1) {
            ++summary.mmioWrites;
          } else {
            ++summary.mmioReads;
          }
          break;
        }
        ++summary.unhandledMmio;
        if (instrLen > 0) {
          vcpu_.AdvanceRip(instrLen);
        } else {
          summary.fatal = true;
          summary.fatalReason = reason;
          captureFatalState();
        }
        break;
      }
      ++summary.unhandledMmio;
      if (instrLen == 0) {
        summary.fatal = true;
        summary.fatalReason = reason;
        captureFatalState();
      } else {
        madeProgress = true;
        vcpu_.AdvanceRip(instrLen);
      }
      break;
    }
    case WHvRunVpExitReasonCanceled:
      try {
        const auto state = vcpu_.ReadDiagState();
        const uint64_t cancelRip =
            ctx.VpContext.Rip != 0 ? ctx.VpContext.Rip : state.rip;
        auto readGpaByte = [&](uint64_t gpa, uint8_t *value) {
          auto *ptr = HostPointerForGpa(gpa, 1);
          if (!ptr) {
            return false;
          }
          *value = *ptr;
          return true;
        };
        uint8_t opcode = 0;
        uint8_t prevOpcode = 0;
        const bool hltAtRip = readGpaByte(cancelRip, &opcode) && opcode == 0xF4u;
        const bool hltBeforeRip =
            cancelRip > 0 && readGpaByte(cancelRip - 1, &prevOpcode) &&
            prevOpcode == 0xF4u;
        const bool canceledAtHlt = hltAtRip || hltBeforeRip;
        summary.lastCanceledRip = cancelRip;
        summary.lastCanceledOpcode = opcode;
        summary.lastCanceledAtHlt = canceledAtHlt;

        if (canceledAtHlt) {
          ++summary.totalHlts;
          if (hltAtRip) {
            vcpu_.AdvanceRip(1);
          }
          injectLapicTimer(vcpu_);
          // A cancellation at HLT is the watchdog catching the guest waiting
          // for an interrupt. The watchdog thread already injects one each
          // tick; treat this as in-progress, not stuck.
          madeProgress = true;
          break;
        }

        if (cancelRip == lastCanceledRip) {
          ++sameCanceledRipStreak;
        } else {
          lastCanceledRip = cancelRip;
          sameCanceledRipStreak = 1;
          madeProgress = true;
        }
      } catch (const WhpError &) {
        ++sameCanceledRipStreak;
      }
      if (sameCanceledRipStreak >= 32) {
        // The vCPU is wedged at the same RIP across many cancellations even
        // though it isn't sitting on a HLT — give up.
        summary.idleLoop = true;
      }
      break;
    default:
      ++summary.unhandledOther;
      summary.fatal = true;
      summary.fatalReason = reason;
      captureFatalState();
      break;
    }

    const uint64_t totalIdeCommands =
        (ide_ ? ide_->CommandsIssued() : 0) +
        (secondaryIde_ ? secondaryIde_->CommandsIssued() : 0);
    if (totalIdeCommands != lastIdeCommands) {
      lastIdeCommands = totalIdeCommands;
      madeProgress = true;
    }

    // After each guest exit, look at the IDE channels for a pending IRQ and
    // try to deliver it. We prefer the IOAPIC redirection (what modern
    // Windows programs for IRQs) and fall back to the legacy PIC vector
    // base for early-boot OVMF, which uses the 8259 path until the IOAPIC
    // is enabled. Either route succeeds when the corresponding controller
    // has been programmed by the guest; otherwise the IRQ stays latched.
    auto tryRaiseLegacyIrq = [&](uint8_t irq) -> IrqDeliveryBackend {
      if (ioApic_.RaiseIrq(irq)) {
        ++summary.irqIoApicDeliveries;
        return IrqDeliveryBackend::IoApic;
      }

      const uint8_t line = static_cast<uint8_t>(irq < 8 ? irq : irq - 8);
      const uint8_t base =
          irq < 8 ? pcIo_.MasterPicVectorBase() : pcIo_.SlavePicVectorBase();
      const uint8_t mask =
          irq < 8 ? pcIo_.MasterPicMask() : pcIo_.SlavePicMask();
      if (base != 0 && (mask & (1u << line)) == 0) {
        const uint8_t vector = static_cast<uint8_t>(base + line);
        if (vcpu_.TryRequestFixedInterrupt(vector)) {
          ++summary.irqPicFallbackDeliveries;
          return IrqDeliveryBackend::PicFallback;
        }
      }

      ++summary.irqDeliveryFailures;
      return IrqDeliveryBackend::Failed;
    };

    if (com1_.InterruptPending()) {
      (void)tryRaiseLegacyIrq(4);
    }
    if (com2_.InterruptPending()) {
      (void)tryRaiseLegacyIrq(3);
    }
    if (const uint8_t irq = ps2_.PendingIrqLine(); irq != 0) {
      (void)tryRaiseLegacyIrq(irq);
    }

    auto tryRaiseIdeIrq = [&](IdeController *controller) {
      if (!controller || !controller->InterruptPending()) {
        return;
      }
      const uint8_t irq = controller->IrqLine();
      ++summary.ideInterruptsRequested;
      const auto backend = tryRaiseLegacyIrq(irq);
      if (backend != IrqDeliveryBackend::Failed) {
        ++summary.ideInterruptsInjected;
        if (backend == IrqDeliveryBackend::IoApic) {
          ++summary.ideInterruptsIoApic;
        } else {
          ++summary.ideInterruptsPicFallback;
        }
        controller->ConsumeInterrupt();
      } else {
        ++summary.ideInterruptsFailed;
      }
    };
    tryRaiseIdeIrq(ide_.get());
    tryRaiseIdeIrq(secondaryIde_.get());

    if (pcIo_.PitInterruptPending()) {
      const auto backend = tryRaiseLegacyIrq(0);
      if (backend != IrqDeliveryBackend::Failed) {
        if (backend == IrqDeliveryBackend::IoApic) {
          ++summary.pitInterruptsIoApic;
        } else {
          ++summary.pitInterruptsPicFallback;
        }
        pcIo_.ConsumePitInterrupt();
      } else {
        ++summary.pitInterruptsFailed;
      }
    }
    if (pcIo_.RtcInterruptPending()) {
      const auto backend = tryRaiseLegacyIrq(8);
      if (backend != IrqDeliveryBackend::Failed) {
        if (backend == IrqDeliveryBackend::IoApic) {
          ++summary.rtcInterruptsIoApic;
        } else {
          ++summary.rtcInterruptsPicFallback;
        }
        pcIo_.ConsumeRtcInterrupt();
      } else {
        ++summary.rtcInterruptsFailed;
      }
    }
    if (madeProgress) {
      stepsSinceProgress = 0;
    } else if (++stepsSinceProgress >= kStuckStepLimit) {
      summary.idleLoop = true;
    }

    const auto now = std::chrono::steady_clock::now();
    if (progressCallback && now - lastProgressFire >= progressInterval) {
      VmProgressSnapshot snapshot{};
      snapshot.steps = summary.steps;
      snapshot.totalHlts = summary.totalHlts;
      snapshot.ideCommandsIssued =
          (ide_ ? ide_->CommandsIssued() : 0) +
          (secondaryIde_ ? secondaryIde_->CommandsIssued() : 0);
      auto sumIde = [](IdeController *c) -> std::pair<uint64_t, uint64_t> {
        return c ? std::pair{c->SectorsRead(), c->SectorsWritten()}
                 : std::pair{uint64_t{0}, uint64_t{0}};
      };
      auto [pr, pw] = sumIde(ide_.get());
      auto [sr, sw] = sumIde(secondaryIde_.get());
      snapshot.ideSectorsRead = pr + sr;
      snapshot.ideSectorsWritten = pw + sw;
      snapshot.mmioReads = summary.mmioReads;
      snapshot.mmioWrites = summary.mmioWrites;
      snapshot.ioApicDeliveries = ioApic_.Deliveries();
      snapshot.timerInterruptsInjected =
          timerInjected.load(std::memory_order_relaxed);
      snapshot.ideInterruptsInjected = summary.ideInterruptsInjected;
      snapshot.elapsed =
          std::chrono::duration_cast<std::chrono::milliseconds>(now -
                                                                runStarted);
      snapshot.newSerialBytes = com1_.PullNew();
      snapshot.newHostChannelBytes = com2_.PullNew();
      {
        // Top-3 IO ports by hit count, biggest first.
        std::array<VmProgressSnapshot::PortHit, 3> top{};
        for (const auto &[port, count] : summary.ioPortHistogram) {
          const auto u = static_cast<uint64_t>(count);
          if (u <= top[2].count) {
            continue;
          }
          if (u > top[0].count) {
            top[2] = top[1];
            top[1] = top[0];
            top[0] = {port, u};
          } else if (u > top[1].count) {
            top[2] = top[1];
            top[1] = {port, u};
          } else {
            top[2] = {port, u};
          }
        }
        for (size_t i = 0; i < 3; ++i) {
          snapshot.topPorts[i] = top[i];
        }
      }
      try {
        const auto diag = vcpu_.ReadDiagState();
        snapshot.currentRip = diag.rip;
        snapshot.currentCsSelector = diag.cs_selector;
        if (ReadGuestMemory(diag.rip, snapshot.ripBytes,
                            sizeof(snapshot.ripBytes))) {
          snapshot.ripBytesValid = true;
        }
      } catch (...) {
        // ReadDiagState can fail in narrow windows around vCPU teardown.
      }
      snapshot.framebufferEnabled = vbe_.Enabled();
      snapshot.framebufferWidth = vbe_.Width();
      snapshot.framebufferHeight = vbe_.Height();
      snapshot.framebufferBpp = vbe_.Bpp();
      snapshot.framebufferHost = vbe_.FramebufferHost();
      snapshot.framebufferBytes = vbe_.FramebufferBytes();
      if (auto *vgaText = HostPointerForGpa(0xB8000ull, 4000)) {
        bool anyNonZero = false;
        for (size_t i = 0; i < 80 * 25; ++i) {
          const auto low =
              static_cast<uint16_t>(vgaText[i * 2]);
          const auto high =
              static_cast<uint16_t>(vgaText[i * 2 + 1]);
          const uint16_t cell = static_cast<uint16_t>((high << 8) | low);
          snapshot.textFramebuffer[i] = cell;
          if (cell != 0) {
            anyNonZero = true;
          }
        }
        snapshot.textFramebufferActive = anyNonZero;
      }
      try {
        progressCallback(snapshot);
      } catch (...) {
        // Progress is best-effort — the VM must not be derailed by a buggy
        // callback. Swallow.
      }
      lastProgressFire = now;
    }

    if (cancelRequested &&
        cancelRequested->load(std::memory_order_relaxed)) {
      summary.hostStopRequested = true;
    }

    if (now >= deadline) {
      summary.timedOut = true;
    }
  }

  inRun.store(false, std::memory_order_relaxed);
  stopApWorkers();
  watchdog.request_stop();
  watchdog.join();
  summary.apStates.clear();
  summary.apStates.reserve(apVcpus_.size());
  for (const auto &ap : apVcpus_) {
    if (!ap) {
      continue;
    }
    VmApRunState apState{};
    apState.index = ap->Index();
    try {
      const auto state = ap->ReadDiagState();
      apState.rip = state.rip;
      apState.csSelector = state.cs_selector;
      apState.ripBytesValid =
          ReadGuestMemoryFor(*ap, state.rip, apState.ripBytes,
                             sizeof(apState.ripBytes));
    } catch (...) {
      apState.rip = 0;
    }
    summary.apStates.push_back(apState);
  }
  if (!summary.fatal &&
      (summary.timedOut || summary.idleLoop || summary.halted)) {
    captureFatalState();
  }
  summary.timerInterruptsRequested =
      timerRequested.load(std::memory_order_relaxed);
  summary.timerInterruptsInjected =
      timerInjected.load(std::memory_order_relaxed);
  summary.watchdogCancellations =
      watchdogCancels.load(std::memory_order_relaxed);
  summary.apVcpuExits = apVcpuExits.load(std::memory_order_relaxed);
  summary.apHltExits = apHltExits.load(std::memory_order_relaxed);
  summary.apCpuidExits = apCpuidExits.load(std::memory_order_relaxed);
  summary.apUnhandledExits =
      apUnhandledExits.load(std::memory_order_relaxed);
  summary.serialOutput = com1_.Captured();
  summary.hostChannelOutput = com2_.Captured();
  if (!pcIo_.DebugOutput().empty()) {
    if (!summary.serialOutput.empty()) {
      summary.serialOutput.append("\n");
    }
    summary.serialOutput.append(pcIo_.DebugOutput());
  }
  summary.ideCommandsIssued = (ide_ ? ide_->CommandsIssued() : 0) +
                              (secondaryIde_ ? secondaryIde_->CommandsIssued()
                                             : 0);
  summary.ideInterruptsPending =
      (ide_ && ide_->InterruptPending() ? 1 : 0) +
      (secondaryIde_ && secondaryIde_->InterruptPending() ? 1 : 0);
  auto collectIde = [&](const std::unique_ptr<IdeController> &controller) {
    if (!controller) {
      return;
    }
    summary.ideIdentifyCommands += controller->IdentifyCommands();
    summary.ideReadCommands += controller->ReadCommands();
    summary.ideWriteCommands += controller->WriteCommands();
    summary.ideAbortedCommands += controller->AbortedCommands();
    summary.ideSectorsRead += controller->SectorsRead();
    summary.ideSectorsWritten += controller->SectorsWritten();
    for (const auto &[command, count] : controller->CommandHistogram()) {
      summary.ideCommandHistogram[command] += static_cast<int>(count);
    }
  };
  collectIde(ide_);
  collectIde(secondaryIde_);
  summary.ioApicRaises = ioApic_.RaiseCount();
  summary.ioApicDeliveries = ioApic_.Deliveries();
  summary.ioApicMaskedDrops = ioApic_.MaskedDrops();
  summary.masterPicVectorBase = pcIo_.MasterPicVectorBase();
  summary.slavePicVectorBase = pcIo_.SlavePicVectorBase();
  summary.masterPicMask = pcIo_.MasterPicMask();
  summary.slavePicMask = pcIo_.SlavePicMask();
  summary.pm1SleepEnable = pcIo_.LastPm1SleepEnable();
  summary.pm1SleepType = pcIo_.LastSleepType();
  summary.pm1ControlValue = pcIo_.LastPm1ControlValue();
  summary.pm1HostStopRequested = pcIo_.LastPm1HostStopRequested();
  summary.pm1SleepRequests = pcIo_.Pm1SleepRequestCount();
  summary.hpetReads = hpet_.Reads();
  summary.hpetWrites = hpet_.Writes();
  summary.pitInterruptsPending = pcIo_.PitInterruptPending() ? 1 : 0;
  summary.rtcInterruptsPending = pcIo_.RtcInterruptPending() ? 1 : 0;
  summary.pitIrqsDelivered = pcIo_.PitIrqCount();
  summary.rtcIrqsDelivered = pcIo_.RtcIrqCount();
  summary.fwCfgFileDirBytesRead = pcIo_.FwCfgFileDirBytesRead();
  summary.fwCfgE820BytesRead = pcIo_.FwCfgE820BytesRead();
  summary.fwCfgAcpiTableBytesRead = pcIo_.FwCfgAcpiTableBytesRead();
  summary.fwCfgTableLoaderBytesRead = pcIo_.FwCfgTableLoaderBytesRead();
  summary.fwCfgRsdpBytesRead = pcIo_.FwCfgRsdpBytesRead();
  const auto &cmos = pcIo_.CmosReadHistogram();
  for (size_t i = 0; i < cmos.size(); ++i) {
    if (cmos[i] != 0) {
      summary.cmosReadHistogram[static_cast<int>(i)] =
          static_cast<int>(cmos[i]);
    }
  }
  // Surface the RIP ring (oldest first) + hotspots + recent CMOS accesses.
  summary.recentRips.reserve(ripRingCount);
  {
    const size_t cap = ripRing.size();
    const size_t start = ripRingCount == cap ? ripRingHead : 0;
    for (size_t i = 0; i < ripRingCount; ++i) {
      summary.recentRips.push_back(ripRing[(start + i) % cap]);
    }
  }
  summary.ripHotspots = std::move(ripHotspots);
  summary.recentCmosAccesses = pcIo_.RecentCmosAccesses();
  for (const uint8_t irq : {uint8_t{0}, uint8_t{3}, uint8_t{4}, uint8_t{8},
                            uint8_t{14}, uint8_t{15}}) {
    summary.legacyIrqDiagnostics.push_back(
        FormatLegacyIrqState(ioApic_, pcIo_, irq));
  }
  summary.crashed = summary.fatal;
  summary.completed = !summary.fatal && !summary.timedOut &&
                      !summary.idleLoop && !summary.halted;
  return summary;
}

} // namespace antimal::hv
