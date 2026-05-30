#include "antimal/hv/VirtualMachine.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdlib>
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
// WHP's Local APIC emulation (WHvX64LocalApicEmulationModeXApic) silently
// maps dummy RAM across the ENTIRE conventional MMIO gap [0xFEC00000,
// 0xFEF00000). WHvUnmapGpaRange "succeeds" but the internal handling
// persists — guest accesses are absorbed without VM exits. Moving devices
// anywhere inside this 3 MiB zone is futile.
//
// Solution: shrink firmwareLowScratch_ to end 512 KiB earlier (at
// 0xFEB80000 instead of 0xFEC00000) and place our MMIO devices in the
// newly created gap [0xFEB80000, 0xFEC00000) which WHP does NOT claim.
// The TPM event log at 0xFEB00000 stays inside the shortened scratch.
constexpr uint64_t kMmioGapStart = 0xFEB80000ull;
constexpr uint64_t kMmioGapEnd = 0xFEF00000ull;
constexpr uint64_t kImageSearchBackBytes = 256ull * 1024ull * 1024ull;

// Relocated MMIO base addresses — below the WHP dummy zone.
constexpr uint64_t kIoApicRelocBase = 0xFEB80000ull;
constexpr uint64_t kHpetRelocBase   = 0xFEB90000ull;
constexpr uint64_t kTpmCrbRelocBase = 0xFEBA0000ull;

// TPM 2.0 event log buffer location in guest physical memory. Sits in the
// firmwareLowScratch_ RAM mapping (0xFC000000-0xFEC00000) so the guest OS
// reads it as ordinary RAM. We pre-populate the first record with the TCG
// EfiSpecIDEvent03 header advertising SHA1 + SHA256 banks; OVMF / winload
// then walk the log via the TPM2 ACPI table's LAML/LASA fields. Without
// this, Microsoft.Windows.Kernel.BootEnvironment / SpacebootInitialize
// aborts the boot with the visible 0xc0430001 WinRE code.
constexpr uint64_t kTpmEventLogGpa = 0xFEB00000ull;
constexpr size_t kTpmEventLogSize = 0x10000;

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

void RecordCpuidSample(VmRunSummary &summary,
                       const CpuidExitResult &sample) {
  for (auto &existing : summary.cpuidSamples) {
    if (existing.vcpuIndex == sample.vcpuIndex && existing.leaf == sample.leaf &&
        existing.subleaf == sample.subleaf) {
      if (sample.overridden && !existing.overridden) {
        existing = sample;
      }
      return;
    }
  }
  constexpr size_t kMaxCpuidSamples = 128;
  if (summary.cpuidSamples.size() < kMaxCpuidSamples) {
    summary.cpuidSamples.push_back(sample);
  }
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
      com2_(SerialConsole::kCom2Base),
      ioApic_(kIoApicRelocBase),
      hpet_(kHpetRelocBase),
      tpm_(kTpmCrbRelocBase) {
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
      // Initialize the TPM 2.0 event log Spec ID Event header inside the
      // firmwareLowScratch RAM region. The first record is the TCG 1.2-format
      // PCR_EVENT carrying a TCG_EfiSpecIDEventStruct payload that tells the
      // OS measured-boot path "this log is TPM 2.0, banks SHA1 + SHA256".
      if (kTpmEventLogGpa >= kFirmwareApertureBase &&
          kTpmEventLogGpa + kTpmEventLogSize <= kMmioGapStart) {
        const auto offset =
            static_cast<size_t>(kTpmEventLogGpa - kFirmwareApertureBase);
        uint8_t *log = firmwareLowScratch_->HostPtr() + offset;
        std::memset(log, 0, kTpmEventLogSize);
        // TCG_PCR_EVENT header (32 bytes + variable event payload):
        //   uint32_t PCRIndex           = 0
        //   uint32_t EventType          = EV_NO_ACTION (0x03)
        //   uint8_t  Digest[20]         = 0
        //   uint32_t EventSize          = sizeof(TCG_EfiSpecIDEventStruct)
        // TCG_EfiSpecIDEventStruct (after PCR_EVENT header):
        //   uint8_t  Signature[16]      = "Spec ID Event03\0"
        //   uint32_t PlatformClass      = 0 (Client)
        //   uint8_t  SpecVersionMinor   = 0
        //   uint8_t  SpecVersionMajor   = 2
        //   uint8_t  SpecErrata         = 0
        //   uint8_t  UintnSize          = 2 (64-bit)
        //   uint32_t NumberOfAlgorithms = 2
        //   TCG_EfiSpecIdEventAlgorithmSize[NumberOfAlgorithms]
        //   uint8_t  VendorInfoSize     = 0
        size_t w = 0;
        auto putLe32 = [&](uint32_t v) {
          log[w++] = static_cast<uint8_t>(v & 0xFF);
          log[w++] = static_cast<uint8_t>((v >> 8) & 0xFF);
          log[w++] = static_cast<uint8_t>((v >> 16) & 0xFF);
          log[w++] = static_cast<uint8_t>((v >> 24) & 0xFF);
        };
        auto putLe16 = [&](uint16_t v) {
          log[w++] = static_cast<uint8_t>(v & 0xFF);
          log[w++] = static_cast<uint8_t>((v >> 8) & 0xFF);
        };
        putLe32(0);                       // PCRIndex
        putLe32(3);                       // EventType = EV_NO_ACTION
        for (int i = 0; i < 20; ++i) {
          log[w++] = 0;                   // Digest (zero for EV_NO_ACTION)
        }
        const size_t eventSizeOffset = w;
        putLe32(0);                       // EventSize placeholder
        const size_t eventStart = w;
        // EfiSpecIDEvent payload
        const char kSig[16] = {'S', 'p', 'e', 'c', ' ', 'I', 'D', ' ',
                               'E', 'v', 'e', 'n', 't', '0', '3', 0};
        for (int i = 0; i < 16; ++i) {
          log[w++] = static_cast<uint8_t>(kSig[i]);
        }
        putLe32(0);                       // PlatformClass = Client
        log[w++] = 0;                     // SpecVersionMinor
        log[w++] = 2;                     // SpecVersionMajor
        log[w++] = 0;                     // SpecErrata
        log[w++] = 2;                     // UintnSize = 2 (64-bit)
        putLe32(2);                       // NumberOfAlgorithms
        putLe16(0x0004);                  // SHA1 algorithm ID
        putLe16(20);                      // SHA1 digest size
        putLe16(0x000B);                  // SHA256 algorithm ID
        putLe16(32);                      // SHA256 digest size
        log[w++] = 0;                     // VendorInfoSize
        const uint32_t eventSize =
            static_cast<uint32_t>(w - eventStart);
        log[eventSizeOffset + 0] = static_cast<uint8_t>(eventSize & 0xFF);
        log[eventSizeOffset + 1] = static_cast<uint8_t>((eventSize >> 8) & 0xFF);
        log[eventSizeOffset + 2] =
            static_cast<uint8_t>((eventSize >> 16) & 0xFF);
        log[eventSizeOffset + 3] =
            static_cast<uint8_t>((eventSize >> 24) & 0xFF);

        // Append TCG_PCR_EVENT2 entries for PCR0..PCR7 with EV_SEPARATOR
        // (TCG_EvSeparator = 0x00000004). Per TCG PC Client Platform
        // Firmware Profile §10.4.1, firmware records a separator event into
        // every PCR in the [0,7] range before invoking the OS loader; OS
        // measured-boot logic uses the separator presence + value to know
        // the firmware phase is complete. Digest = SHA1/SHA256 of
        // {0xFF,0xFF,0xFF,0xFF}. EventData = same 4 bytes.
        constexpr uint8_t kSepSha1[20] = {
            0xD9, 0xBE, 0x65, 0x24, 0xA5, 0xF5, 0x04, 0x7D, 0xB5, 0x86,
            0x68, 0x13, 0xAC, 0xF3, 0x27, 0x78, 0x92, 0xA7, 0xA3, 0x0A};
        constexpr uint8_t kSepSha256[32] = {
            0xAD, 0x95, 0x13, 0x1B, 0xC0, 0xB7, 0x99, 0xC0, 0xB1, 0xAF,
            0x47, 0x7F, 0xB1, 0x4F, 0xCF, 0x26, 0xA6, 0xA9, 0xF7, 0x60,
            0x79, 0xE4, 0x8B, 0xF0, 0x90, 0xAC, 0xB7, 0xE8, 0x36, 0x7B,
            0xFD, 0x0E};
        constexpr uint32_t kEvSeparator = 0x00000004;
        for (uint32_t pcr = 0; pcr < 8; ++pcr) {
          if (w + 120 > kTpmEventLogSize) break;
          putLe32(pcr);                  // PCRIndex
          putLe32(kEvSeparator);         // EventType
          putLe32(2);                    // DigestValues.count
          // SHA1 digest
          putLe16(0x0004);               // alg = SHA1
          for (uint8_t b : kSepSha1) log[w++] = b;
          // SHA256 digest
          putLe16(0x000B);               // alg = SHA256
          for (uint8_t b : kSepSha256) log[w++] = b;
          // EventSize + EventData (separator value)
          putLe32(4);
          log[w++] = 0xFF;
          log[w++] = 0xFF;
          log[w++] = 0xFF;
          log[w++] = 0xFF;
        }
        tpmEventLogBytesWritten_ = static_cast<uint32_t>(w);
        tpmEventLogPopulated_ = true;
        // Mirror these separator extends into the in-stub PCR banks so
        // PCR_Read returns the same digests the log advertises.
        for (uint32_t pcr = 0; pcr < 8; ++pcr) {
          tpm_.ExtendInternal(pcr, /*algId=*/0x0004, kSepSha1, 20);
          tpm_.ExtendInternal(pcr, /*algId=*/0x000B, kSepSha256, 32);
        }
      }
    }
    if (fwGpa > kMmioGapEnd) {
      const auto upperSize = static_cast<size_t>(fwGpa - kMmioGapEnd);
      firmwareUpperScratch_ = std::make_unique<GuestMemoryRegion>(
          host_, kMmioGapEnd, upperSize,
          GuestMemoryProt::ReadWriteExecute);
      std::memset(firmwareUpperScratch_->HostPtr(), 0, upperSize);
    }
  }
  // WHP's Local APIC emulation (xAPIC mode) silently maps internal dummy
  // pages at the canonical IOAPIC (0xFEC00000), HPET (0xFED00000), and
  // TPM CRB (0xFED40000) GPAs. These pages absorb guest reads/writes
  // without VM exits, defeating our software device emulators.
  //
  // Scan the entire MMIO gap [0xFEC00000, 0xFEF00000) at 64-KiB stride
  // via WHvUnmapGpaRange. A successful unmap means WHP had the page
  // mapped — the bitmap tells us exactly how wide the interference zone
  // is, so we can choose a relocation target outside it.
  {
    constexpr uint64_t kGapBase = 0xFEC00000ull;
    constexpr uint64_t kGapEnd = 0xFEF00000ull;
    constexpr uint64_t kStride = 0x10000ull;
    for (uint64_t gpa = kGapBase; gpa < kGapEnd; gpa += kStride) {
      const HRESULT hr = WHvUnmapGpaRange(host_.Handle(), gpa, 0x1000);
      if (SUCCEEDED(hr)) {
        const uint64_t bit = (gpa - kGapBase) / kStride;
        if (bit < 64) {
          whpMmioGapBitmap_ |= (1ull << bit);
        }
        whpIoApicGpaProbeResult_ = 1;
      }
    }
  }

  PcIoMemoryLayout layout{};
  layout.lowRamBytes =
      pageTableAssistBase_ != 0 ? pageTableAssistBase_ : options.lowRamBytes;
  layout.highRamBytes = options.highRamBytes;
  pcIo_.SetMemoryLayout(layout);
  // Tell the ACPI table builder about the relocated MMIO bases so the MADT,
  // HPET, and TPM2 tables advertise addresses that match our actual devices.
  pcIo_.SetMmioBaseAddresses(kIoApicRelocBase, kHpetRelocBase,
                             kTpmCrbRelocBase);
  tpm2TableEnabled_ = options.enableTpm2Table;
  pcIo_.SetTpm2TableEnabled(tpm2TableEnabled_);
  pcIo_.SetProcessorCount(host_.ProcessorCount());
  pcIo_.SetAcpiTablesEnabled(options.enableAcpiTables);
  if (tpmEventLogPopulated_) {
    pcIo_.SetTpmEventLog(kTpmEventLogGpa,
                          static_cast<uint32_t>(kTpmEventLogSize));
  }
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
  mmioBus_.Attach(&tpm_);
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

  // Bus-master IDE (BMDMA / BAR4). The IdeController performs real PRD-table DMA
  // between disk and guest RAM, so give each channel a guest-physical memory
  // accessor and attach its 8-port BMDMA register block. BAR4 is OS-relocatable;
  // attach at the current base now and re-attach in the IO-exit handler when the
  // guest reassigns it. Primary channel = base+0..7, secondary = base+8..15.
  auto dmaMem = [this](uint64_t gpa, std::size_t len) -> uint8_t * {
    return HostPointerForGpa(gpa, len);
  };
  ide_->SetDmaMemory(dmaMem);
  secondaryIde_->SetDmaMemory(dmaMem);
  const uint16_t bmBase = pcIo_.IdeBmdmaBase();
  ide_->SetBmdmaBase(bmBase);
  bus_.Attach(ide_.get(), bmBase, static_cast<uint16_t>(bmBase + 7));
  secondaryIde_->SetBmdmaBase(static_cast<uint16_t>(bmBase + 8));
  bus_.Attach(secondaryIde_.get(), static_cast<uint16_t>(bmBase + 8),
              static_cast<uint16_t>(bmBase + 15));
  pcIo_.ConsumeBmdmaAttachDirty();
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

bool VirtualMachine::TryEmulateSimpleMmioAccess(
    const WHV_RUN_VP_EXIT_CONTEXT &exit, IMmioDevice *device, bool *isWrite) {
  if (!device || !isWrite) {
    return false;
  }
  *isWrite = false;

  uint8_t instr[16]{};
  if (!ReadGuestMemoryFor(vcpu_, exit.VpContext.Rip, instr, sizeof(instr))) {
    return false;
  }

  size_t pos = 0;
  bool operand16 = false;
  bool rexPresent = false;
  uint8_t rex = 0;
  while (pos < sizeof(instr)) {
    const uint8_t b = instr[pos];
    if (b == 0x66) {
      operand16 = true;
      ++pos;
      continue;
    }
    if (b >= 0x40 && b <= 0x4F) {
      rexPresent = true;
      rex = b;
      ++pos;
      continue;
    }
    break;
  }
  if (pos + 2 > sizeof(instr)) {
    return false;
  }

  const uint8_t opcode = instr[pos++];
  const bool writeToMem = opcode == 0x88 || opcode == 0x89;
  const bool readFromMem = opcode == 0x8A || opcode == 0x8B;
  if (!writeToMem && !readFromMem) {
    return false;
  }
  const bool byteAccess = opcode == 0x88 || opcode == 0x8A;
  const uint8_t modrm = instr[pos++];
  const uint8_t mod = (modrm >> 6) & 0x3u;
  const uint8_t reg =
      static_cast<uint8_t>(((modrm >> 3) & 0x7u) | ((rex & 0x4u) ? 8u : 0u));
  const uint8_t rm = static_cast<uint8_t>(modrm & 0x7u);
  if (mod == 0x3u) {
    return false;
  }
  if (rm == 0x4u) {
    if (pos >= sizeof(instr)) {
      return false;
    }
    ++pos; // SIB byte.
  }
  if (mod == 0x0u && rm == 0x5u) {
    pos += 4;
  } else if (mod == 0x1u) {
    pos += 1;
  } else if (mod == 0x2u) {
    pos += 4;
  }
  if (pos > sizeof(instr)) {
    return false;
  }

  const uint8_t accessSize =
      byteAccess ? 1 : operand16 ? 2 : (rex & 0x8u) ? 8 : 4;
  if (accessSize != 1 && accessSize != 2 && accessSize != 4 &&
      accessSize != 8) {
    return false;
  }

  static constexpr WHV_REGISTER_NAME kRegs[16] = {
      WHvX64RegisterRax, WHvX64RegisterRcx, WHvX64RegisterRdx,
      WHvX64RegisterRbx, WHvX64RegisterRsp, WHvX64RegisterRbp,
      WHvX64RegisterRsi, WHvX64RegisterRdi, WHvX64RegisterR8,
      WHvX64RegisterR9,  WHvX64RegisterR10, WHvX64RegisterR11,
      WHvX64RegisterR12, WHvX64RegisterR13, WHvX64RegisterR14,
      WHvX64RegisterR15};
  WHV_REGISTER_VALUE regs[16]{};
  if (FAILED(WHvGetVirtualProcessorRegisters(vcpu_.Partition(), vcpu_.Index(),
                                             kRegs, 16, regs))) {
    return false;
  }

  auto readReg = [&](uint8_t index) -> uint64_t {
    if (index >= 16) {
      return 0;
    }
    const uint64_t full = regs[index].Reg64;
    if (accessSize == 1) {
      if (!rexPresent && index >= 4 && index <= 7) {
        return (full >> 8) & 0xFFu;
      }
      return full & 0xFFu;
    }
    if (accessSize == 2) {
      return full & 0xFFFFu;
    }
    if (accessSize == 4) {
      return full & 0xFFFFFFFFu;
    }
    return full;
  };

  auto writeReg = [&](uint8_t index, uint64_t value) -> bool {
    if (index >= 16) {
      return false;
    }
    uint64_t full = regs[index].Reg64;
    if (accessSize == 1) {
      if (!rexPresent && index >= 4 && index <= 7) {
        full = (full & ~0xFF00ull) | ((value & 0xFFu) << 8);
      } else {
        full = (full & ~0xFFull) | (value & 0xFFu);
      }
    } else if (accessSize == 2) {
      full = (full & ~0xFFFFull) | (value & 0xFFFFu);
    } else if (accessSize == 4) {
      full = value & 0xFFFFFFFFu;
    } else {
      full = value;
    }
    WHV_REGISTER_VALUE out{};
    out.Reg64 = full;
    return SUCCEEDED(WHvSetVirtualProcessorRegisters(
        vcpu_.Partition(), vcpu_.Index(), &kRegs[index], 1, &out));
  };

  if (writeToMem) {
    if (!device->OnWrite(exit.MemoryAccess.Gpa, accessSize, readReg(reg))) {
      return false;
    }
    *isWrite = true;
  } else {
    uint64_t value = 0;
    if (!device->OnRead(exit.MemoryAccess.Gpa, accessSize, &value) ||
        !writeReg(reg, value)) {
      return false;
    }
  }

  vcpu_.AdvanceRip(pos);
  return true;
}

bool VirtualMachine::IdentifyGuestImage(uint64_t gva, VmGuestImageInfo *info) {
  // Accept both low (user, bits 48-63 clear) and high-canonical (kernel, bits
  // 48-63 set) addresses; reject only non-canonical ones. The old guard
  // (gva>>48)!=0 rejected EVERY kernel address, so a stall RIP in ntoskrnl/a
  // driver (0xFFFFF80x...) never got its module/PDB resolved -- which is exactly
  // what we need to identify a Phase-1 kernel spin. The MZ scan-back below walks
  // down from the page, so high-canonical input is required to find the module.
  const bool canonical = (gva >> 47) == 0 || (gva >> 47) == 0x1FFFFull;
  if (!info || gva == 0 || gva == UINT64_MAX || !canonical) {
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
                         request.cancelRequested, request.keyboardScancodes,
                         request.keyboardInjectAfter,
                         request.keyboardBursts);
  summary.networkMode = request.networkMode;
  return summary;
}

VmRunSummary VirtualMachine::RunLoop(
    int maxSteps, std::chrono::steady_clock::time_point deadline,
    const VmProgressCallback &progressCallback,
    std::chrono::milliseconds progressInterval,
    std::shared_ptr<std::atomic_bool> cancelRequested,
    std::vector<uint8_t> keyboardScancodes,
    std::chrono::milliseconds keyboardInjectAfter,
    std::vector<VmRunRequest::KeyboardBurst> keyboardBursts) {
  VmRunSummary summary;
  summary.started = true;
  summary.processorCount = host_.ProcessorCount();
  // Diagnostic: attempt to unmap WHP's internal dummy pages at the canonical
  // MMIO GPAs one last time. This no longer affects correctness because our
  // devices are relocated to non-canonical GPAs (kIoApicRelocBase, etc.),
  // but the attempt confirms whether WHP re-maps between setup and first run.
  {
    constexpr uint64_t kReclaimPages[][2] = {
        {0xFEC00000ull, 0x1000},
        {0xFED00000ull, 0x1000},
        {0xFED40000ull, 0x1000},
    };
    for (auto &[gpa, size] : kReclaimPages) {
      (void)WHvUnmapGpaRange(host_.Handle(), gpa, size);
    }
  }
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
  // Deliver the guest's programmed IOAPIC clock (the 8254 PIT, remapped to GSI2
  // by the MADT ISO) at a steady real cadence from the watchdog thread. The
  // run loop only raises GSI2 on guest *exits*, which collapse to ~1/s once the
  // kernel idles -> the system clock (KeUpdateSystemTime on vector 0xD1) crawls
  // and Phase-1 time-waits never expire. Injecting entry[2]'s vector here keeps
  // the kernel's wall clock advancing like real hardware does. Inert until the
  // guest programs+unmasks GSI2, so OVMF-only smoke tests are unaffected.
  auto injectIoApicClock = [&](Vcpu &cpu) {
    const uint64_t rte = ioApic_.RedirectionEntry(2);
    const bool masked = (rte & (1ull << 16)) != 0;
    const uint8_t vector = static_cast<uint8_t>(rte & 0xFFu);
    if (!masked && vector >= 0x10) {
      (void)cpu.TryRequestFixedInterrupt(vector);
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
        injectIoApicClock(vcpu_);
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
  // Re-injected #PF loop guard: if the identical (RIP, CR2) fault recurs this
  // many times in a row the guest can neither resolve nor unwind it, so we stop
  // re-injecting and treat it as fatal. Generous so it never trips on normal
  // boot behaviour (an SEH probe unwinds away from the faulting RIP after one
  // re-injection; demand paging resolves and the retry succeeds).
  constexpr int kMaxReinjectedFaultStreak = 256;
  uint64_t lastReinjectedFaultRip = 0;
  uint64_t lastReinjectedFaultCr2 = ~0ull;
  int reinjectedFaultStreak = 0;
  // Opt-in: NOP OVMF's runtime tick-wait spin in guest RAM when the kernel hits
  // it (a UEFI runtime service whose firmware tick freezes once the OS owns the
  // interrupt controllers). See fwSpinPatches in the summary.
  const bool kFwSpinNop =
      std::getenv("ANTIMAL_PROBE_FWSPIN_NOP") != nullptr;
  int stepsSinceProgress = 0;
  uint64_t lastIdeCommands = 0;
  const auto runStarted = std::chrono::steady_clock::now();
  auto lastProgressFire = runStarted;
  bool keyboardInjected = keyboardScancodes.empty();
  KdSerialDebugger kdDebugger;
  size_t kdCom1Cursor = 0;
  auto queueKdHostReset = [&](const char *reason) {
    kdDebugger.QueueHostReset(reason);
    const auto replies = kdDebugger.PullReplies();
    if (!replies.empty()) {
      com1_.QueueRxBytes(replies);
    }
  };
  queueKdHostReset("initial host KD reset/resync probe");
  auto lastKdHostReset = runStarted;
  uint32_t kdHostResetBursts = 1;
  constexpr uint32_t kKdHostResetBurstLimit = 60;
  constexpr auto kKdHostResetInterval = std::chrono::milliseconds(500);

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
  auto captureLowRamImages = [&](std::vector<VmGuestImageInfo> *images,
                                 size_t limit) {
    if (!images || images->size() >= limit) {
      return;
    }
    const auto *lowBytes = lowRam_.HostPtr();
    for (uint64_t gpa = 0;
         lowBytes && gpa + kPageSize <= lowRam_.Size() &&
         images->size() < limit;
         gpa += kPageSize) {
      const auto offset = static_cast<size_t>(gpa);
      if (lowBytes[offset] != 'M' || lowBytes[offset + 1] != 'Z') {
        continue;
      }
      const bool duplicate = std::any_of(
          images->begin(), images->end(),
          [&](const VmGuestImageInfo &seen) { return seen.base == gpa; });
      if (duplicate) {
        continue;
      }
      VmGuestImageInfo image{};
      if (IdentifyGuestImage(gpa, &image) && image.valid &&
          image.base == gpa) {
        images->push_back(std::move(image));
      }
    }
  };
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
        // Deep stack scan: collect every kernel-image return pointer on the BSP
        // stack as RVAs (the call chain). Plus an optional KiBugCheckData read
        // (ANTIMAL_BUGCHECK_DATA_RVA) to recover the bugcheck code + params.
        if (summary.fatalRipImage.valid && summary.fatalRipImage.base != 0) {
          const uint64_t kbase = summary.fatalRipImage.base;
          const uint64_t ksize = summary.fatalRipImage.sizeOfImage;
          summary.deepStackImageBase = kbase;
          std::array<uint8_t, 0x1000> stk{};
          if (summary.fatalRsp != 0 &&
              ReadGuestMemory(summary.fatalRsp, stk.data(), stk.size())) {
            for (size_t off = 0;
                 off + 8 <= stk.size() && summary.deepStackCount < 64;
                 off += 8) {
              uint64_t v = 0;
              std::memcpy(&v, stk.data() + off, sizeof(v));
              if (v >= kbase && v < kbase + ksize) {
                summary.deepStackRvas[summary.deepStackCount++] = v - kbase;
              }
            }
          }
          if (const char *rvaEnv = std::getenv("ANTIMAL_BUGCHECK_DATA_RVA")) {
            const uint64_t bcRva =
                std::strtoull(rvaEnv, nullptr, 0);
            uint64_t bc[5] = {0, 0, 0, 0, 0};
            if (bcRva != 0 &&
                ReadGuestMemory(kbase + bcRva, bc, sizeof(bc))) {
              summary.bugCheckDataValid = true;
              std::memcpy(summary.bugCheckData, bc, sizeof(bc));
            }
          }
          // PsLoadedModuleList walk: enumerate the loaded kernel modules at the
          // bugcheck (name + base + load order). This answers the decisive 0x7B
          // question -- did pciide/atapi/intelide/ataport/disk actually LOAD --
          // entirely from guest memory, no kernel debugger needed. RVA is
          // build-specific (ntoskrnl PDB); pass ANTIMAL_PSLOADEDMODULELIST_RVA.
          // _LIST_ENTRY head; each node is a _KLDR_DATA_TABLE_ENTRY with
          // InLoadOrderLinks@0x0, DllBase@0x30, SizeOfImage@0x40,
          // BaseDllName(UNICODE_STRING)@0x58 (Length@0x58, Buffer@0x60).
          if (const char *plmEnv =
                  std::getenv("ANTIMAL_PSLOADEDMODULELIST_RVA")) {
            const uint64_t plmRva = std::strtoull(plmEnv, nullptr, 0);
            uint64_t flink = 0;
            const uint64_t head = kbase + plmRva;
            if (plmRva != 0 && ReadGuestMemory(head, &flink, sizeof(flink))) {
              std::string list;
              uint32_t count = 0;
              for (uint64_t node = flink;
                   node != head && node != 0 && count < 192; ++count) {
                uint16_t nameLen = 0;
                uint64_t nameBuf = 0;
                ReadGuestMemory(node + 0x58, &nameLen, sizeof(nameLen));
                ReadGuestMemory(node + 0x60, &nameBuf, sizeof(nameBuf));
                char nm[64] = {0};
                if (nameBuf != 0 && nameLen >= 2) {
                  const uint16_t nbytes = nameLen > 126 ? 126 : nameLen;
                  std::array<uint16_t, 64> wbuf{};
                  if (ReadGuestMemory(nameBuf, wbuf.data(), nbytes)) {
                    const size_t chars = static_cast<size_t>(nbytes) / 2;
                    for (size_t i = 0; i < chars && i < 63; ++i) {
                      nm[i] = (wbuf[i] >= 0x20 && wbuf[i] < 0x7F)
                                  ? static_cast<char>(wbuf[i])
                                  : '?';
                    }
                  }
                }
                if (!list.empty()) {
                  list += ' ';
                }
                list += (nm[0] != 0 ? nm : "<noname>");
                uint64_t next = 0;
                if (!ReadGuestMemory(node, &next, sizeof(next))) {
                  break;
                }
                node = next;
              }
              summary.loadedModules = list;
              summary.loadedModuleCount = count;
            }
          }
          // Interpret bugcheck p1 as a PUNICODE_STRING for 0x7B: the I/O manager
          // frequently passes the ARC/NT device path it failed to open. Reading
          // it tells us WHAT the kernel was waiting for (vs. assuming the IDE).
          if (summary.bugCheckDataValid &&
              (summary.bugCheckData[0] & 0xFFFFFFFFull) == 0x7Bull) {
            const uint64_t p1 = summary.bugCheckData[1];
            uint16_t len = 0;
            uint64_t buf = 0;
            if (p1 != 0 && ReadGuestMemory(p1, &len, sizeof(len)) &&
                ReadGuestMemory(p1 + 0x8, &buf, sizeof(buf)) && len >= 2 &&
                len <= 520 && buf != 0) {
              const uint16_t nbytes = len > 510 ? 510 : len;
              std::array<uint16_t, 256> wbuf{};
              if (ReadGuestMemory(buf, wbuf.data(), nbytes)) {
                std::string s;
                const size_t chars = static_cast<size_t>(nbytes) / 2;
                for (size_t i = 0; i < chars && i < 255; ++i) {
                  s += (wbuf[i] >= 0x20 && wbuf[i] < 0x7F)
                           ? static_cast<char>(wbuf[i])
                           : '?';
                }
                summary.bootDeviceFailPath = s;
              }
            }
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
      captureFatalState();
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
      // BAR4 (bus-master IDE) is OS-relocatable. If the guest just reassigned it
      // via a PCI config write, re-attach each channel's 8-port BMDMA block to
      // its IdeController at the new base (primary base+0..7, secondary +8..15)
      // so subsequent BMDMA accesses reach the controller's PRD DMA engine.
      if (pcIo_.ConsumeBmdmaAttachDirty()) {
        const uint16_t bmBase = pcIo_.IdeBmdmaBase();
        if (bmBase != 0 && ide_) {
          ide_->SetBmdmaBase(bmBase);
          bus_.Attach(ide_.get(), bmBase, static_cast<uint16_t>(bmBase + 7));
          if (secondaryIde_) {
            secondaryIde_->SetBmdmaBase(static_cast<uint16_t>(bmBase + 8));
            bus_.Attach(secondaryIde_.get(),
                        static_cast<uint16_t>(bmBase + 8),
                        static_cast<uint16_t>(bmBase + 15));
          }
        }
      }
      vcpu_.AdvanceRip(instrLen != 0 ? instrLen : io.InstructionByteCount);
      break;
    }
    case WHvRunVpExitReasonX64Cpuid:
      madeProgress = true;
      summary.cpuidLeafHistogram[
          static_cast<uint32_t>(ctx.CpuidAccess.Rax)]++;
      RecordCpuidSample(summary, vcpu_.EmulateCpuidExit());
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
      // Not a host-assisted firmware fault: this is the guest's own page fault
      // (kernel demand paging, copy-on-write, a guard page, or an SEH-protected
      // probe such as ProbeForRead touching MmUserProbeAddress=0x7FFFFFFF0000).
      // On hardware the guest's IDT #PF handler resolves or SEH-unwinds it, so
      // re-inject it rather than killing the VM. WHP delivers it through the
      // guest IDT with CR2 set from the faulting address. This is the gate that
      // used to murder the boot the instant ntoskrnl ran its first probe.
      if (ex.ExceptionType == WHvX64ExceptionTypePageFault) {
        const uint64_t faultRip = ctx.VpContext.Rip;
        if (faultRip == lastReinjectedFaultRip &&
            ex.ExceptionParameter == lastReinjectedFaultCr2) {
          ++reinjectedFaultStreak;
        } else {
          lastReinjectedFaultRip = faultRip;
          lastReinjectedFaultCr2 = ex.ExceptionParameter;
          reinjectedFaultStreak = 1;
        }
        if (reinjectedFaultStreak < kMaxReinjectedFaultStreak &&
            vcpu_.TryInjectPageFault(ex.ExceptionParameter, ex.ErrorCode)) {
          ++summary.pageFaultsReinjected;
          summary.lastReinjectedFaultGva = ex.ExceptionParameter;
          summary.lastReinjectedFaultErrorCode = ex.ErrorCode;
          madeProgress = true;
          break;
        }
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
      ++summary.totalBspMemoryAccessExits;
      if (summary.totalBspMemoryAccessExits == 1) {
        summary.firstBspMemoryAccessGpa = gpa;
      }
      summary.lastBspMemoryAccessGpa = gpa;
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
        bool fallbackWrite = false;
        if (TryEmulateSimpleMmioAccess(ctx, device, &fallbackWrite)) {
          madeProgress = true;
          if (fallbackWrite) {
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
        // RFLAGS.IF set => the guest is INTERRUPTIBLE: it is waiting for an
        // interrupt (KiIdleLoop's STI;HLT, a clock/event wait, the idle helper
        // we park in between ticks), not hard-wedged. A healthy booting kernel
        // runs with IF=1 and advances on each clock tick / DPC. Only a guest
        // spinning with interrupts DISABLED (IF=0) at one RIP is a true wedge.
        // Without this, the idleLoop detector murdered the kernel the instant
        // it reached its idle loop (Phase 1, bootvid spinner already animating).
        const bool interruptsEnabled = (state.rflags & 0x200ull) != 0;
        summary.lastCanceledRip = cancelRip;
        summary.lastCanceledOpcode = opcode;
        summary.lastCanceledAtHlt = canceledAtHlt;

        // OVMF runtime tick-wait bypass. The Windows kernel calls a UEFI runtime
        // service; OVMF's runtime driver spins "wait until *tick changes" but the
        // tick is frozen (OVMF's timer ISR no longer runs once the OS owns the
        // PIC/APIC) -> deadlock. Detect the exact signature
        //   cmp rdx,rax; jne +4; pause; jmp -0x14; leave; ret
        //   (48 39 C2 75 04 F3 90 EB EC C9 C3)
        // around the canceled RIP and NOP the back-jump (EB EC -> 90 90) in
        // guest RAM so the wait falls through to leave;ret and returns. Patch is
        // in disposable guest RAM only; self-limiting (after the patch the bytes
        // are 90 90, so the signature no longer matches).
        if (kFwSpinNop) {
          static const uint8_t kSig[] = {0x48, 0x39, 0xC2, 0x75, 0x04, 0xF3,
                                         0x90, 0xEB, 0xEC, 0xC9, 0xC3};
          std::array<uint8_t, 0x40> win{};
          const uint64_t winBase = cancelRip > 0x20 ? cancelRip - 0x20 : 0;
          if (ReadGuestMemory(winBase, win.data(), win.size())) {
            for (size_t i = 0; i + sizeof(kSig) <= win.size(); ++i) {
              if (std::memcmp(win.data() + i, kSig, sizeof(kSig)) == 0) {
                const uint64_t jmpGva = winBase + i + 7; // EB EC offset
                // Write at the physical level: runtime code pages are mapped
                // read-only/execute, so a write-honoring path would fault. We
                // are the hypervisor -> patch the backing page directly.
                uint64_t gpa = 0;
                if (vcpu_.TryTranslateGva(jmpGva, false, &gpa)) {
                  if (auto *p = HostPointerForGpa(gpa, 2)) {
                    p[0] = 0x90;
                    p[1] = 0x90;
                    ++summary.fwSpinPatches;
                    summary.lastFwSpinPatchGva = jmpGva;
                    madeProgress = true;
                  }
                }
                break;
              }
            }
          }
        }

        if (canceledAtHlt || interruptsEnabled) {
          if (canceledAtHlt) {
            ++summary.totalHlts;
            if (hltAtRip) {
              vcpu_.AdvanceRip(1);
            }
          }
          injectLapicTimer(vcpu_);
          // The watchdog caught the guest waiting for an interrupt (at HLT or
          // simply with interrupts enabled). The watchdog + IOAPIC keep feeding
          // ticks; treat this as in-progress, not stuck, and reset the wedge
          // streak so a healthy idle never trips the idleLoop kill.
          sameCanceledRipStreak = 0;
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
        // though it isn't sitting on a HLT â€” give up.
        summary.idleLoop = true;
      }
      break;
    case WHvRunVpExitReasonX64InterruptWindow:
      // WHP raises this (exit reason 7) when an interrupt is pending but the
      // guest currently can't take it (RFLAGS.IF=0 or an interrupt shadow). We
      // don't arm deliverability notifications, so this is rare, but it is
      // never fatal: re-assert the LAPIC timer tick and continue so WHP
      // delivers the pending interrupt once the guest re-enables interrupts.
      injectLapicTimer(vcpu_);
      madeProgress = true;
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
      captureLowRamImages(&summary.observedImages, 256);
      madeProgress = true;
    }

    const auto kdBytes = com1_.PullSince(kdCom1Cursor);
    kdCom1Cursor = com1_.CapturedBytes();
    if (!kdBytes.empty()) {
      const auto beforePackets = kdDebugger.Summary().packetsReceived;
      kdDebugger.PushBytes(kdBytes);
      const auto replies = kdDebugger.PullReplies();
      if (!replies.empty()) {
        com1_.QueueRxBytes(replies);
        madeProgress = true;
      }
      if (kdDebugger.Summary().packetsReceived != beforePackets) {
        madeProgress = true;
      }
    }
    const auto nowForKd = std::chrono::steady_clock::now();
    if (kdDebugger.Summary().bytesObserved == 0 &&
        kdHostResetBursts < kKdHostResetBurstLimit &&
        nowForKd - lastKdHostReset >= kKdHostResetInterval &&
        !com1_.RxDataReady()) {
      queueKdHostReset("periodic host KD reset/resync probe");
      lastKdHostReset = nowForKd;
      ++kdHostResetBursts;
    }

    // After each guest exit, look at the IDE channels for a pending IRQ and
    // try to deliver it. We prefer the IOAPIC redirection (what modern
    // Windows programs for IRQs) and fall back to the legacy PIC vector
    // base for early-boot OVMF, which uses the 8259 path until the IOAPIC
    // is enabled. Either route succeeds when the corresponding controller
    // has been programmed by the guest; otherwise the IRQ stays latched.
    auto tryRaiseLegacyIrq = [&](uint8_t irq) -> IrqDeliveryBackend {
      // The MADT publishes an Interrupt Source Override remapping ISA IRQ0
      // (the 8254 PIT) to GSI2, so the guest programs the IOAPIC's input pin 2
      // — not pin 0 — for the periodic clock. Apply the same ISA->GSI remap
      // when raising the line on the IOAPIC; otherwise the PIT tick hits the
      // still-masked pin 0 and is dropped, and the early kernel spins forever
      // on the clock it wired to pin 2 (entry[2]: vector 0xD1, unmasked, the
      // ONLY programmed redirection entry). All other ISA IRQs are identity
      // (the SCI's IRQ9->GSI9 override keeps the same index). The 8259 PIC
      // fallback below deliberately keeps the raw ISA line — the PIC has no
      // Interrupt Source Override concept.
      const uint8_t ioApicGsi = (irq == 0) ? 2u : irq;
      if (ioApic_.RaiseIrq(ioApicGsi)) {
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
    if (!keyboardInjected && now - runStarted >= keyboardInjectAfter) {
      ps2_.InjectKeyboardScancodes(keyboardScancodes.data(),
                                   keyboardScancodes.size());
      summary.keyboardScancodesInjected +=
          static_cast<int>(keyboardScancodes.size());
      keyboardInjected = true;
      madeProgress = true;
    }
    for (auto &burst : keyboardBursts) {
      if (!burst.scancodes.empty() && now - runStarted >= burst.delay) {
        ps2_.InjectKeyboardScancodes(burst.scancodes.data(),
                                     burst.scancodes.size());
        summary.keyboardScancodesInjected +=
            static_cast<int>(burst.scancodes.size());
        burst.scancodes.clear();
        madeProgress = true;
      }
    }
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
        // Progress is best-effort â€” the VM must not be derailed by a buggy
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
  summary.firmwareDebugOutput = pcIo_.DebugOutput();
  summary.hostChannelOutput = com2_.Captured();
  const auto com1Stats = com1_.Stats();
  summary.com1RegisterReads = com1Stats.registerReads;
  summary.com1RegisterWrites = com1Stats.registerWrites;
  summary.com1DataReads = com1Stats.dataReads;
  summary.com1DataWrites = com1Stats.dataWrites;
  summary.com1RxBytesQueued = com1Stats.rxBytesQueued;
  summary.com1RxBytesRead = com1Stats.rxBytesRead;
  summary.com1RxBytesCleared = com1Stats.rxBytesCleared;
  summary.com1IerWrites = com1Stats.ierWrites;
  summary.com1FcrWrites = com1Stats.fcrWrites;
  summary.com1LcrWrites = com1Stats.lcrWrites;
  summary.com1McrWrites = com1Stats.mcrWrites;
  summary.com1DllWrites = com1Stats.dllWrites;
  summary.com1DlmWrites = com1Stats.dlmWrites;
  summary.com1IirReads = com1Stats.iirReads;
  summary.com1LsrReads = com1Stats.lsrReads;
  summary.com1Ier = com1Stats.ier;
  summary.com1Fcr = com1Stats.fcr;
  summary.com1Lcr = com1Stats.lcr;
  summary.com1Mcr = com1Stats.mcr;
  summary.com1Dll = com1Stats.dll;
  summary.com1Dlm = com1Stats.dlm;
  summary.com1Dlab = com1Stats.dlab;
  summary.com1RxInterruptEnabled = com1Stats.rxInterruptEnabled;
  summary.com1RxDataReady = com1Stats.rxDataReady;
  summary.kdCom1RxQueuedBytes = com1_.RxQueuedBytes();
  summary.kdSummary = kdDebugger.Summary();
  summary.kdEvents = kdDebugger.Events();
  summary.kdTranscript = kdDebugger.Transcript();
  summary.kdPacketsJsonl = kdDebugger.PacketsJsonl();
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
    if (controller->SawRead()) {
      if (!summary.ideSawRead) {
        summary.ideMinReadLba = controller->MinReadLba();
        summary.ideMaxReadEndLba = controller->MaxReadEndLba();
        summary.ideSawRead = true;
      } else {
        summary.ideMinReadLba =
            std::min(summary.ideMinReadLba, controller->MinReadLba());
        summary.ideMaxReadEndLba =
            std::max(summary.ideMaxReadEndLba, controller->MaxReadEndLba());
      }
    }
    if (controller->SawWrite()) {
      if (!summary.ideSawWrite) {
        summary.ideMinWriteLba = controller->MinWriteLba();
        summary.ideMaxWriteEndLba = controller->MaxWriteEndLba();
        summary.ideSawWrite = true;
      } else {
        summary.ideMinWriteLba =
            std::min(summary.ideMinWriteLba, controller->MinWriteLba());
        summary.ideMaxWriteEndLba =
            std::max(summary.ideMaxWriteEndLba, controller->MaxWriteEndLba());
      }
    }
    const auto &recent = controller->RecentAccesses();
    summary.ideRecentAccesses.insert(summary.ideRecentAccesses.end(),
                                     recent.begin(), recent.end());
    constexpr size_t kMaxSummaryIdeAccesses = 4096;
    if (summary.ideRecentAccesses.size() > kMaxSummaryIdeAccesses) {
      summary.ideRecentAccesses.erase(
          summary.ideRecentAccesses.begin(),
          summary.ideRecentAccesses.begin() +
              (summary.ideRecentAccesses.size() - kMaxSummaryIdeAccesses));
    }
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
  summary.masterPicIcw1Writes = pcIo_.MasterPicIcw1Writes();
  summary.slavePicIcw1Writes = pcIo_.SlavePicIcw1Writes();
  summary.masterPicIcw2Value = pcIo_.MasterPicIcw2Value();
  summary.slavePicIcw2Value = pcIo_.SlavePicIcw2Value();
  for (uint32_t i = 0; i < IoApic::kRedirectionEntries; ++i) {
    summary.ioApicRedir[i] = ioApic_.RedirectionEntry(i);
    summary.ioApicWrites[i] = ioApic_.WriteCount(i);
  }
  summary.ideConfigSelects = pcIo_.IdeConfigSelects();
  summary.whpIoApicGpaProbe = whpIoApicGpaProbeResult_;
  summary.whpMmioGapBitmap = whpMmioGapBitmap_;
  summary.tpm2TableEnabled = tpm2TableEnabled_;
  summary.pm1SleepEnable = pcIo_.LastPm1SleepEnable();
  summary.pm1SleepType = pcIo_.LastSleepType();
  summary.pm1ControlValue = pcIo_.LastPm1ControlValue();
  summary.pm1HostStopRequested = pcIo_.LastPm1HostStopRequested();
  summary.pm1SleepRequests = pcIo_.Pm1SleepRequestCount();
  summary.hpetReads = hpet_.Reads();
  summary.hpetWrites = hpet_.Writes();
  if (tpmEventLogPopulated_) {
    summary.tpmEventLogLaml = static_cast<uint32_t>(kTpmEventLogSize);
    summary.tpmEventLogLasa = kTpmEventLogGpa;
  }
  summary.tpmCrbReads = tpm_.Reads();
  summary.tpmCrbWrites = tpm_.Writes();
  summary.tpmCrbCommands = tpm_.CommandsProcessed();
  summary.tpmCrbLastCommand = tpm_.LastCommandCode();
  summary.tpmCrbLastResponse = tpm_.LastResponseCode();
  summary.tpmCrbLastReadOffset = tpm_.LastReadOffset();
  summary.tpmCrbLastWriteOffset = tpm_.LastWriteOffset();
  summary.tpmCrbCommandHistogram = tpm_.CommandHistogram();
  summary.tpmCrbRecentCommands = tpm_.RecentCommands();
  summary.tpmPcrExtendTrace = tpm_.PcrExtendTrace();
  summary.tpmPcrSha1Bank = tpm_.PcrSha1Bank();
  summary.tpmPcrSha256Bank = tpm_.PcrSha256Bank();
  summary.pitInterruptsPending = pcIo_.PitInterruptPending() ? 1 : 0;
  summary.rtcInterruptsPending = pcIo_.RtcInterruptPending() ? 1 : 0;
  summary.ps2StatusReads = ps2_.StatusReads();
  summary.ps2DataReads = ps2_.DataReads();
  summary.ps2CommandWrites = ps2_.CommandWrites();
  summary.ps2DataWrites = ps2_.DataWrites();
  summary.ps2KeyboardBytesQueued = ps2_.KeyboardBytesQueued();
  summary.ps2KeyboardBytesRead = ps2_.KeyboardBytesRead();
  summary.ps2MouseBytesQueued = ps2_.MouseBytesQueued();
  summary.ps2MouseBytesRead = ps2_.MouseBytesRead();
  summary.ps2KeyboardPortEnabled = ps2_.KeyboardPortEnabled();
  summary.ps2MousePortEnabled = ps2_.MousePortEnabled();
  summary.ps2KeyboardScanningEnabled = ps2_.KeyboardScanningEnabled();
  summary.pitIrqsDelivered = pcIo_.PitIrqCount();
  summary.rtcIrqsDelivered = pcIo_.RtcIrqCount();
  summary.fwCfgFileDirBytesRead = pcIo_.FwCfgFileDirBytesRead();
  summary.fwCfgE820BytesRead = pcIo_.FwCfgE820BytesRead();
  summary.fwCfgAcpiTableBytesRead = pcIo_.FwCfgAcpiTableBytesRead();
  summary.fwCfgTableLoaderBytesRead = pcIo_.FwCfgTableLoaderBytesRead();
  summary.fwCfgRsdpBytesRead = pcIo_.FwCfgRsdpBytesRead();
  summary.fwCfgSmbiosTableBytesRead = pcIo_.FwCfgSmbiosTableBytesRead();
  summary.fwCfgSmbiosAnchorBytesRead = pcIo_.FwCfgSmbiosAnchorBytesRead();
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
  {
    std::vector<std::pair<uint64_t, uint64_t>> topRipHotspots(
        summary.ripHotspots.begin(), summary.ripHotspots.end());
    std::sort(topRipHotspots.begin(), topRipHotspots.end(),
              [](const auto &a, const auto &b) {
                return a.second > b.second;
              });
    constexpr size_t kMaxHotspotImageSamples = 16;
    if (topRipHotspots.size() > kMaxHotspotImageSamples) {
      topRipHotspots.resize(kMaxHotspotImageSamples);
    }
    summary.ripHotspotImages.reserve(topRipHotspots.size());
    for (const auto &[ripBucket, hits] : topRipHotspots) {
      VmRipHotspotImageInfo sample{};
      sample.ripBucket = ripBucket;
      sample.hits = hits;
      (void)IdentifyGuestImage(ripBucket, &sample.image);
      sample.ripBytesValid =
          ReadGuestMemory(ripBucket, sample.ripBytes, sizeof(sample.ripBytes));
      summary.ripHotspotImages.push_back(std::move(sample));
    }
  }
  // UEFI loads PE images on page boundaries while Boot Manager still uses
  // firmware services. The observed set covers transient images; this final
  // sweep reports the smaller resident set that survived until shutdown.
  captureLowRamImages(&summary.observedImages, 256);
  captureLowRamImages(&summary.residentImages, 128);
  summary.recentCmosAccesses = pcIo_.RecentCmosAccesses();
  for (const uint8_t irq : {uint8_t{0}, uint8_t{1}, uint8_t{3}, uint8_t{4},
                            uint8_t{8}, uint8_t{12}, uint8_t{14},
                            uint8_t{15}}) {
    summary.legacyIrqDiagnostics.push_back(
        FormatLegacyIrqState(ioApic_, pcIo_, irq));
  }
  summary.crashed = summary.fatal;
  summary.completed = !summary.fatal && !summary.timedOut &&
                      !summary.idleLoop && !summary.halted;
  return summary;
}

} // namespace antimal::hv
