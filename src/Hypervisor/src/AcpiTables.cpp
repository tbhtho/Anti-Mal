#include "antimal/hv/AcpiTables.h"

#include "antimal/hv/Hpet.h"
#include "antimal/hv/Tpm2CrbDevice.h"

#include <algorithm>
#include <cstring>
#include <initializer_list>
#include <stdexcept>
#include <string_view>

namespace antimal::hv {
namespace {

constexpr const char *kAcpiTablesFile = "etc/acpi/tables";
constexpr const char *kTableLoaderFile = "etc/table-loader";
constexpr const char *kRsdpFile = "etc/acpi/rsdp";
constexpr uint8_t kLoaderZoneHigh = 1;
constexpr uint8_t kLoaderZoneFseg = 2;
constexpr uint32_t kPmIoBase = 0xB000;
constexpr uint32_t kPm1EventBlock = kPmIoBase;
constexpr uint32_t kPm1ControlBlock = kPmIoBase + 0x04;
constexpr uint32_t kPmTimerBlock = kPmIoBase + 0x08;

void PutLe16(std::vector<uint8_t> &out, uint16_t value) {
  out.push_back(static_cast<uint8_t>(value & 0xFFu));
  out.push_back(static_cast<uint8_t>((value >> 8) & 0xFFu));
}

void PutLe32(std::vector<uint8_t> &out, uint32_t value) {
  for (int i = 0; i < 4; ++i) {
    out.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFFu));
  }
}

void PutLe64(std::vector<uint8_t> &out, uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    out.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFFu));
  }
}

void AppendGas(std::vector<uint8_t> &out, uint8_t addressSpace,
               uint8_t bitWidth, uint8_t bitOffset, uint8_t accessSize,
               uint64_t address) {
  out.push_back(addressSpace);
  out.push_back(bitWidth);
  out.push_back(bitOffset);
  out.push_back(accessSize);
  PutLe64(out, address);
}

void WriteLe32(std::vector<uint8_t> &out, size_t offset, uint32_t value) {
  if (offset + 4 > out.size()) {
    throw std::out_of_range("ACPI write past end");
  }
  for (int i = 0; i < 4; ++i) {
    out[offset + static_cast<size_t>(i)] =
        static_cast<uint8_t>((value >> (i * 8)) & 0xFFu);
  }
}

void AppendFixedAscii(std::vector<uint8_t> &out, std::string_view text,
                      size_t bytes, char pad = ' ') {
  for (size_t i = 0; i < bytes; ++i) {
    out.push_back(i < text.size() ? static_cast<uint8_t>(text[i])
                                  : static_cast<uint8_t>(pad));
  }
}

uint32_t BeginSdt(std::vector<uint8_t> &out, std::string_view signature,
                  uint8_t revision) {
  const auto offset = static_cast<uint32_t>(out.size());
  AppendFixedAscii(out, signature, 4, '\0');
  PutLe32(out, 0); // Length patched by EndSdt.
  out.push_back(revision);
  out.push_back(0); // Checksum patched by EndSdt.
  // Anti-evasion: the ACPI OEM identity must NOT spell out a sandbox name (any
  // sample enumerating ACPI tables would detect "ANTIMAL" by string). Present the
  // canonical real-PC AMI signature instead -- these are not hypervisor markers,
  // and the checksum is recomputed by the loader (EndSdt leaves it 0), so this is
  // boot-safe. OEMID / OEM Table ID / OEM Creator ID:
  AppendFixedAscii(out, "ALASKA", 6);
  AppendFixedAscii(out, "A M I", 8);
  PutLe32(out, 1);
  AppendFixedAscii(out, "INTL", 4);
  PutLe32(out, 0x20190703);
  return offset;
}

void EndSdt(std::vector<uint8_t> &out, uint32_t offset) {
  const uint32_t length = static_cast<uint32_t>(out.size() - offset);
  WriteLe32(out, offset + 4, length);
  // Leave the SDT checksum byte (offset 9) ZERO. The fw_cfg table-loader's
  // ADD_CHECKSUM command fills it at load time as CalculateCheckSum8 =
  // 0x100 - Sum8(range). That range INCLUDES the checksum byte and OVMF does
  // NOT pre-zero it (QemuFwCfgAcpi.c: Blob[ResultOffset] = CalculateCheckSum8(
  // Start, Length)). So if we pre-store a non-zero checksum V here, OVMF's
  // recompute yields a final Sum8 == -V != 0, and EVERY SDT fails OVMF's
  // ACPI-header validation -> "installed 1 tables" (only the FACS, which has
  // no checksum byte, survives) -> the MADT never reaches the guest ->
  // winload's OslpDetermineKernelHal returns STATUS_NOT_FOUND (0xC0000225).
  // The byte MUST be 0 pre-loader.
  out[offset + 9] = 0;
}

void AppendPkgLength(std::vector<uint8_t> &out, size_t bodyBytes) {
  for (uint8_t byteCount = 1; byteCount <= 4; ++byteCount) {
    const size_t encodedValue = bodyBytes + byteCount;
    const size_t maxValue = byteCount == 1 ? 0x3Fu
                            : byteCount == 2 ? 0x0FFFu
                            : byteCount == 3 ? 0x0FFFFFu
                                             : 0x0FFFFFFFu;
    if (encodedValue > maxValue) {
      continue;
    }
    if (byteCount == 1) {
      out.push_back(static_cast<uint8_t>(encodedValue & 0x3Fu));
      return;
    }
    out.push_back(static_cast<uint8_t>(((byteCount - 1u) << 6u) |
                                       (encodedValue & 0x0Fu)));
    size_t remaining = encodedValue >> 4u;
    for (uint8_t i = 1; i < byteCount; ++i) {
      out.push_back(static_cast<uint8_t>(remaining & 0xFFu));
      remaining >>= 8u;
    }
    return;
  }
  throw std::runtime_error("AML package too large");
}

std::vector<uint8_t> NameSeg(std::string_view name) {
  std::vector<uint8_t> out;
  out.resize(4, '_');
  for (size_t i = 0; i < std::min<size_t>(4, name.size()); ++i) {
    out[i] = static_cast<uint8_t>(name[i]);
  }
  return out;
}

void AppendByteConst(std::vector<uint8_t> &out, uint8_t value) {
  if (value == 0) {
    out.push_back(0x00); // ZeroOp
  } else if (value == 1) {
    out.push_back(0x01); // OneOp
  } else {
    out.push_back(0x0A); // BytePrefix
    out.push_back(value);
  }
}

void AppendDwordConst(std::vector<uint8_t> &out, uint32_t value) {
  out.push_back(0x0C); // DWordPrefix
  PutLe32(out, value);
}

void AppendName(std::vector<uint8_t> &out, std::string_view name,
                const std::vector<uint8_t> &object) {
  out.push_back(0x08); // NameOp
  const auto seg = NameSeg(name);
  out.insert(out.end(), seg.begin(), seg.end());
  out.insert(out.end(), object.begin(), object.end());
}

std::vector<uint8_t> IntegerObject(uint32_t value) {
  std::vector<uint8_t> out;
  if (value <= 0xFFu) {
    AppendByteConst(out, static_cast<uint8_t>(value));
  } else {
    AppendDwordConst(out, value);
  }
  return out;
}

std::vector<uint8_t> PackageObject(
    const std::vector<std::vector<uint8_t>> &elements) {
  if (elements.size() > 0xFFu) {
    throw std::runtime_error("AML package has too many elements");
  }

  std::vector<uint8_t> body;
  body.push_back(static_cast<uint8_t>(elements.size()));
  for (const auto &element : elements) {
    body.insert(body.end(), element.begin(), element.end());
  }

  std::vector<uint8_t> out;
  out.push_back(0x12); // PackageOp
  AppendPkgLength(out, body.size());
  out.insert(out.end(), body.begin(), body.end());
  return out;
}

std::vector<uint8_t> EisaObject(const char id[8]) {
  std::vector<uint8_t> out;
  AppendDwordConst(out, AcpiEisaId(id));
  return out;
}

std::vector<uint8_t> ResourceTemplate(const std::vector<uint8_t> &bytes) {
  std::vector<uint8_t> body;
  if (bytes.size() > 0xFFu) {
    throw std::runtime_error("ACPI resource template too large");
  }
  body.push_back(0x0A); // BytePrefix for BufferSize.
  body.push_back(static_cast<uint8_t>(bytes.size()));
  body.insert(body.end(), bytes.begin(), bytes.end());

  std::vector<uint8_t> out;
  out.push_back(0x11); // BufferOp
  AppendPkgLength(out, body.size());
  out.insert(out.end(), body.begin(), body.end());
  return out;
}

void AppendIoDescriptor(std::vector<uint8_t> &out, uint16_t base,
                        uint8_t length) {
  out.push_back(0x47); // Small IO descriptor, 7 bytes.
  out.push_back(0x01); // 16-bit decode.
  PutLe16(out, base);
  PutLe16(out, base);
  out.push_back(length);
  out.push_back(length);
}

void AppendMemory32FixedDescriptor(std::vector<uint8_t> &out, uint32_t base,
                                   uint32_t length, bool writable) {
  out.push_back(0x86); // Fixed memory range descriptor.
  PutLe16(out, 9);
  out.push_back(writable ? 0x01 : 0x00);
  PutLe32(out, base);
  PutLe32(out, length);
}

void AppendWordAddressSpaceDescriptor(std::vector<uint8_t> &out,
                                      uint8_t resourceType,
                                      uint16_t granularity,
                                      uint16_t minimum, uint16_t maximum,
                                      uint16_t translation,
                                      uint16_t length) {
  out.push_back(0x88); // Word address-space descriptor.
  PutLe16(out, 13);
  out.push_back(resourceType);
  out.push_back(0x0D); // ResourceProducer, MinFixed, MaxFixed, PosDecode.
  out.push_back(0x00);
  PutLe16(out, granularity);
  PutLe16(out, minimum);
  PutLe16(out, maximum);
  PutLe16(out, translation);
  PutLe16(out, length);
}

void AppendDwordAddressSpaceDescriptor(std::vector<uint8_t> &out,
                                       uint8_t resourceType,
                                       uint32_t granularity,
                                       uint32_t minimum, uint32_t maximum,
                                       uint32_t translation,
                                       uint32_t length,
                                       uint8_t typeFlags = 0x00) {
  out.push_back(0x87); // DWord address-space descriptor.
  PutLe16(out, 23);
  out.push_back(resourceType);
  out.push_back(0x0D); // ResourceProducer, MinFixed, MaxFixed, PosDecode.
  out.push_back(typeFlags);
  PutLe32(out, granularity);
  PutLe32(out, minimum);
  PutLe32(out, maximum);
  PutLe32(out, translation);
  PutLe32(out, length);
}

void AppendIrqDescriptor(std::vector<uint8_t> &out, uint8_t irq) {
  out.push_back(0x22); // IRQ descriptor, 2 bytes.
  PutLe16(out, static_cast<uint16_t>(1u << irq));
}

void AppendEndTag(std::vector<uint8_t> &out) {
  out.push_back(0x79);
  out.push_back(0x00);
}

std::vector<uint8_t> DeviceObject(std::string_view name,
                                  const std::vector<uint8_t> &terms) {
  std::vector<uint8_t> body;
  const auto seg = NameSeg(name);
  body.insert(body.end(), seg.begin(), seg.end());
  body.insert(body.end(), terms.begin(), terms.end());

  std::vector<uint8_t> out;
  out.push_back(0x5B);
  out.push_back(0x82); // DeviceOp
  AppendPkgLength(out, body.size());
  out.insert(out.end(), body.begin(), body.end());
  return out;
}

std::vector<uint8_t> ScopeObject(std::string_view name,
                                 const std::vector<uint8_t> &terms) {
  std::vector<uint8_t> body;
  const auto seg = NameSeg(name);
  body.insert(body.end(), seg.begin(), seg.end());
  body.insert(body.end(), terms.begin(), terms.end());

  std::vector<uint8_t> out;
  out.push_back(0x10); // ScopeOp
  AppendPkgLength(out, body.size());
  out.insert(out.end(), body.begin(), body.end());
  return out;
}

std::vector<uint8_t> ProcessorObject(std::string_view name, uint8_t id) {
  std::vector<uint8_t> body;
  const auto seg = NameSeg(name);
  body.insert(body.end(), seg.begin(), seg.end());
  body.push_back(id);
  PutLe32(body, 0); // PBlk address.
  body.push_back(0); // PBlk length.

  std::vector<uint8_t> out;
  out.push_back(0x5B);
  out.push_back(0x83); // ProcessorOp.
  AppendPkgLength(out, body.size());
  out.insert(out.end(), body.begin(), body.end());
  return out;
}

std::vector<uint8_t> DeviceWithResources(std::string_view name,
                                         const char hid[8], uint8_t uid,
                                         const std::vector<uint8_t> &resources) {
  std::vector<uint8_t> terms;
  AppendName(terms, "_HID", EisaObject(hid));
  AppendName(terms, "_UID", IntegerObject(uid));
  AppendName(terms, "_STA", IntegerObject(0x0F));
  AppendName(terms, "_CRS", ResourceTemplate(resources));
  return DeviceObject(name, terms);
}

std::vector<uint8_t> PciRoutingEntry(uint8_t device, uint8_t pin,
                                     uint8_t irq) {
  const uint32_t address =
      (static_cast<uint32_t>(device) << 16u) | 0xFFFFu;
  return PackageObject({IntegerObject(address), IntegerObject(pin),
                        IntegerObject(0), IntegerObject(irq)});
}

std::vector<uint8_t> BuildDsdtAml(uint32_t processorCount) {
  std::vector<uint8_t> rootTerms;
  AppendName(rootTerms, "_S5",
             PackageObject({IntegerObject(5), IntegerObject(5),
                            IntegerObject(0), IntegerObject(0)}));

  // \_PIC control method. Windows evaluates \_PIC(1) early in boot to tell the
  // platform it chose the APIC interrupt model. CRITICAL: if \_PIC is absent,
  // an OS running in APIC mode interprets PCI0._PRT source indices as legacy
  // 8259 PIC IRQs and routes PCI device interrupts to the (masked) PICs instead
  // of the IOAPIC -- those interrupts then vanish into the dead PIC. The IDE no
  // longer rides _PRT (it is compat-mode and uses legacy IRQ14/15 via the MADT
  // identity mapping -- see PCI0._PRT below), but any PCI device that does use an
  // INTx pin (e.g. the VGA on dev 2 -> GSI10) still depends on \_PIC being
  // present so its _PRT GSI is programmed on the IOAPIC, not the masked PIC.
  // Encoding: MethodOp(0x14) PkgLen(6) "_PIC"(5F 50 49 43) MethodFlags(0x01 =
  // 1 arg, not serialized) with an empty body -- Windows only requires the
  // method to exist and be callable; our _PRT already returns hardwired GSIs.
  {
    static const uint8_t kPicMethod[] = {0x14, 0x06, 0x5F,
                                         0x50, 0x49, 0x43, 0x01};
    rootTerms.insert(rootTerms.end(), kPicMethod,
                     kPicMethod + sizeof(kPicMethod));
  }

  std::vector<uint8_t> sbTerms;

  const uint32_t cpuCount = std::clamp<uint32_t>(processorCount, 1, 64);
  for (uint32_t cpu = 0; cpu < cpuCount; ++cpu) {
    char name[5] = {'C', 'P', 'U',
                    static_cast<char>('0' + (cpu % 10u)), '\0'};
    if (cpu >= 10) {
      name[2] = static_cast<char>('A' + ((cpu / 10u) - 1u));
    }
    const auto proc =
        ProcessorObject(name, static_cast<uint8_t>(cpu & 0xFFu));
    sbTerms.insert(sbTerms.end(), proc.begin(), proc.end());
  }

  std::vector<uint8_t> pciTerms;
  AppendName(pciTerms, "_HID", EisaObject("PNP0A03"));
  AppendName(pciTerms, "_UID", IntegerObject(0));
  AppendName(pciTerms, "_BBN", IntegerObject(0));
  AppendName(pciTerms, "_ADR", IntegerObject(0));
  std::vector<uint8_t> pciResources;
  AppendWordAddressSpaceDescriptor(pciResources, 0x02, 0, 0x0000, 0x00FF,
                                   0, 0x0100);
  AppendDwordAddressSpaceDescriptor(pciResources, 0x01, 0, 0x00000000,
                                    0x0000CFFF, 0, 0x0000D000);
  AppendDwordAddressSpaceDescriptor(pciResources, 0x01, 0, 0x0000D000,
                                    0x0000FFFF, 0, 0x00003000);
  AppendDwordAddressSpaceDescriptor(pciResources, 0x00, 0, 0x80000000,
                                    0xFEBFFFFF, 0, 0x7EC00000, 0x01);
  AppendEndTag(pciResources);
  AppendName(pciTerms, "_CRS", ResourceTemplate(pciResources));
  // _PRT maps PCI INTx pins to GSIs. The compat-mode IDE (dev 1) uses the
  // LEGACY IRQ14/15 lines directly (config Interrupt Pin = 0, no PCI INTx), and
  // those legacy IRQs map to GSI14/15 via the MADT's identity mapping -- NOT via
  // _PRT. So dev 1 must NOT appear here: a dev1-INTA->GSI14 / dev1-INTB->GSI15
  // entry makes Windows reserve GSI14/15 for the PCI interrupt pool, which then
  // collides with the IDE channel's legacy IRQ14 claim -- the PCIIDE\IDEChannel
  // devnode then fails to start with CM_PROB_NORMAL_CONFLICT (prob=12, observed
  // run 77cda7d0), atapi never binds, the boot disk is never enumerated -> 0x7B.
  // (Those dev1 entries were a leftover from an abandoned approach that drove
  // the IDE interrupt through PCI INTA.) The VGA (dev 2 INTA -> GSI10) and the
  // AHCI SATA HBA (dev 3 INTA -> GSI11) are PCI-native and DO ride _PRT: their
  // INTx interrupts arbitrate in PCI scope, which is exactly why AHCI works
  // where the compat IDE's ISA IRQ14 could not be granted.
  // dev 4 INTA -> GSI 11 is the e1000 NIC (present only with ANTIMAL_ENABLE_NIC),
  // sharing AHCI's PCI INTx GSI. Harmless when the NIC is absent: GSI 11 is
  // already in the PCI pool for AHCI, so this reserves no new line, and Windows
  // finds no device at dev 4 to route to.
  AppendName(pciTerms, "_PRT",
             PackageObject({PciRoutingEntry(2, 0, 10),
                            PciRoutingEntry(3, 0, 11),
                            PciRoutingEntry(4, 0, 11)}));

  std::vector<uint8_t> isaTerms;
  AppendName(isaTerms, "_ADR", IntegerObject(0x00010000u));
  AppendName(isaTerms, "_STA", IntegerObject(0x0F));
  const auto isa = DeviceObject("ISA_", isaTerms);
  pciTerms.insert(pciTerms.end(), isa.begin(), isa.end());

  std::vector<uint8_t> pmTerms;
  AppendName(pmTerms, "_ADR", IntegerObject(0x00010003u));
  AppendName(pmTerms, "_STA", IntegerObject(0x0F));
  const auto pm = DeviceObject("PMIO", pmTerms);
  pciTerms.insert(pciTerms.end(), pm.begin(), pm.end());

  std::vector<uint8_t> vgaTerms;
  AppendName(vgaTerms, "_ADR", IntegerObject(0x00020000u));
  AppendName(vgaTerms, "_STA", IntegerObject(0x0F));
  const auto vga = DeviceObject("VGA_", vgaTerms);
  pciTerms.insert(pciTerms.end(), vga.begin(), vga.end());

  // AHCI SATA controller at PCI 00:03.0 (8086:2922). Declared so the _PRT
  // dev-3 INTA->GSI11 routing has a matching namespace device; storahci binds
  // the PCI-enumerated function and drives the boot disk.
  std::vector<uint8_t> ahciTerms;
  AppendName(ahciTerms, "_ADR", IntegerObject(0x00030000u));
  AppendName(ahciTerms, "_STA", IntegerObject(0x0F));
  const auto ahci = DeviceObject("SATA", ahciTerms);
  pciTerms.insert(pciTerms.end(), ahci.begin(), ahci.end());

  const auto pci = DeviceObject("PCI0", pciTerms);
  sbTerms.insert(sbTerms.end(), pci.begin(), pci.end());

  std::vector<uint8_t> pic;
  AppendIoDescriptor(pic, 0x0020, 2);
  AppendIoDescriptor(pic, 0x00A0, 2);
  AppendIrqDescriptor(pic, 2);
  AppendEndTag(pic);
  const auto picDev = DeviceWithResources("PIC_", "PNP0000", 0, pic);
  sbTerms.insert(sbTerms.end(), picDev.begin(), picDev.end());

  std::vector<uint8_t> timr;
  AppendIoDescriptor(timr, 0x0040, 4);
  AppendIrqDescriptor(timr, 0);
  AppendEndTag(timr);
  const auto timrDev = DeviceWithResources("TIMR", "PNP0100", 0, timr);
  sbTerms.insert(sbTerms.end(), timrDev.begin(), timrDev.end());

  std::vector<uint8_t> rtc;
  AppendIoDescriptor(rtc, 0x0070, 2);
  AppendIrqDescriptor(rtc, 8);
  AppendEndTag(rtc);
  const auto rtcDev = DeviceWithResources("RTC0", "PNP0B00", 0, rtc);
  sbTerms.insert(sbTerms.end(), rtcDev.begin(), rtcDev.end());

  std::vector<uint8_t> pmio;
  AppendIoDescriptor(pmio, static_cast<uint16_t>(kPmIoBase), 0x40);
  AppendEndTag(pmio);
  const auto pmioDev = DeviceWithResources("PMRS", "PNP0C02", 0, pmio);
  sbTerms.insert(sbTerms.end(), pmioDev.begin(), pmioDev.end());

  std::vector<uint8_t> hpet;
  AppendMemory32FixedDescriptor(hpet, HpetDevice::kDefaultMmioBase, 0x400,
                                true);
  AppendEndTag(hpet);
  const auto hpetDev = DeviceWithResources("HPET", "PNP0103", 0, hpet);
  sbTerms.insert(sbTerms.end(), hpetDev.begin(), hpetDev.end());

  std::vector<uint8_t> com1;
  AppendIoDescriptor(com1, 0x03F8, 8);
  AppendIrqDescriptor(com1, 4);
  AppendEndTag(com1);
  const auto com1Dev = DeviceWithResources("COM1", "PNP0501", 1, com1);
  sbTerms.insert(sbTerms.end(), com1Dev.begin(), com1Dev.end());

  std::vector<uint8_t> com2;
  AppendIoDescriptor(com2, 0x02F8, 8);
  AppendIrqDescriptor(com2, 3);
  AppendEndTag(com2);
  const auto com2Dev = DeviceWithResources("COM2", "PNP0501", 2, com2);
  sbTerms.insert(sbTerms.end(), com2Dev.begin(), com2Dev.end());

  std::vector<uint8_t> ps2k;
  AppendIoDescriptor(ps2k, 0x0060, 1);
  AppendIoDescriptor(ps2k, 0x0064, 1);
  AppendIrqDescriptor(ps2k, 1);
  AppendEndTag(ps2k);
  const auto ps2kDev = DeviceWithResources("PS2K", "PNP0303", 0, ps2k);
  sbTerms.insert(sbTerms.end(), ps2kDev.begin(), ps2kDev.end());

  std::vector<uint8_t> ps2m;
  AppendIrqDescriptor(ps2m, 12);
  AppendEndTag(ps2m);
  const auto ps2mDev = DeviceWithResources("PS2M", "PNP0F13", 0, ps2m);
  sbTerms.insert(sbTerms.end(), ps2mDev.begin(), ps2mDev.end());

  const auto sbScope = ScopeObject("_SB_", sbTerms);
  rootTerms.insert(rootTerms.end(), sbScope.begin(), sbScope.end());
  return rootTerms;
}

uint32_t AppendFacs(std::vector<uint8_t> &out) {
  const auto offset = static_cast<uint32_t>(out.size());
  AppendFixedAscii(out, "FACS", 4, '\0');
  PutLe32(out, 64);
  PutLe32(out, 0); // Hardware signature.
  PutLe32(out, 0); // Firmware waking vector.
  PutLe32(out, 0); // Global lock.
  PutLe32(out, 0); // Flags.
  out.insert(out.end(), 40, 0); // ACPI 1.0b reserved bytes.
  return offset;
}

uint32_t AppendDsdt(std::vector<uint8_t> &out, uint32_t processorCount) {
  const auto offset = BeginSdt(out, "DSDT", 2);
  const auto aml = BuildDsdtAml(processorCount);
  out.insert(out.end(), aml.begin(), aml.end());
  EndSdt(out, offset);
  return offset;
}

uint32_t AppendFadt(std::vector<uint8_t> &out, uint32_t facsOffset,
                    uint32_t dsdtOffset) {
  const auto offset = BeginSdt(out, "FACP", 3);
  PutLe32(out, facsOffset); // FirmwareCtrl, adjusted by table-loader.
  PutLe32(out, dsdtOffset); // DSDT, adjusted by table-loader.
  out.push_back(1);      // INT_MODEL: multiple APIC.
  out.push_back(1);      // Preferred PM profile: desktop.
  PutLe16(out, 9);       // SCI interrupt.
  PutLe32(out, 0);       // SMI command port.
  out.push_back(0);      // ACPI enable.
  out.push_back(0);      // ACPI disable.
  out.push_back(0);      // S4BIOS request.
  out.push_back(0);      // P-state control.
  PutLe32(out, kPm1EventBlock); // PM1a event block.
  PutLe32(out, 0);       // PM1b event block.
  PutLe32(out, kPm1ControlBlock); // PM1a control block.
  PutLe32(out, 0);       // PM1b control block.
  PutLe32(out, 0);       // PM2 control block.
  PutLe32(out, kPmTimerBlock); // PM timer block.
  PutLe32(out, 0);       // GPE0 block.
  PutLe32(out, 0);       // GPE1 block.
  out.push_back(4);      // PM1 event length.
  out.push_back(2);      // PM1 control length.
  out.push_back(0);      // PM2 control length.
  out.push_back(4);      // PM timer length.
  out.push_back(0);      // GPE0 length.
  out.push_back(0);      // GPE1 length.
  out.push_back(0);      // GPE1 base.
  out.push_back(0);      // C-state control.
  PutLe16(out, 0);       // C2 latency.
  PutLe16(out, 0);       // C3 latency.
  PutLe16(out, 0);       // Flush size.
  PutLe16(out, 0);       // Flush stride.
  out.push_back(0);      // Duty offset.
  out.push_back(0);      // Duty width.
  out.push_back(0);      // Day alarm.
  out.push_back(0);      // Month alarm.
  out.push_back(0);      // Century.
  PutLe16(out, 0x0003);  // Legacy devices + 8042 present.
  out.push_back(0);      // Reserved.
  PutLe32(out, 0x000004A5);
  AppendGas(out, 1, 8, 0, 1, 0xCF9); // Reset register (I/O port).
  out.push_back(0x06);          // Reset value.
  out.insert(out.end(), 3, 0);  // Reserved.
  PutLe64(out, facsOffset);     // X_FirmwareCtrl.
  PutLe64(out, dsdtOffset);     // X_Dsdt.
  AppendGas(out, 1, 32, 0, 3, kPm1EventBlock);
  AppendGas(out, 1, 0, 0, 0, 0);
  AppendGas(out, 1, 16, 0, 2, kPm1ControlBlock);
  AppendGas(out, 1, 0, 0, 0, 0);
  AppendGas(out, 1, 0, 0, 0, 0);
  AppendGas(out, 1, 32, 0, 3, kPmTimerBlock);
  AppendGas(out, 1, 0, 0, 0, 0);
  AppendGas(out, 1, 0, 0, 0, 0);
  EndSdt(out, offset);
  return offset;
}

uint32_t AppendMadt(std::vector<uint8_t> &out, uint32_t processorCount,
                    uint64_t ioApicBase) {
  const auto offset = BeginSdt(out, "APIC", 1);
  PutLe32(out, 0xFEE00000u); // Local APIC address.
  PutLe32(out, 1);           // PC-AT compatibility.

  const uint32_t cpuCount = std::clamp<uint32_t>(processorCount, 1, 64);
  for (uint32_t cpu = 0; cpu < cpuCount; ++cpu) {
    out.push_back(0); // Processor local APIC.
    out.push_back(8);
    out.push_back(static_cast<uint8_t>(cpu & 0xFFu)); // ACPI processor UID.
    out.push_back(static_cast<uint8_t>(cpu & 0xFFu)); // APIC ID.
    PutLe32(out, 1); // Enabled.
  }

  out.push_back(1); // IOAPIC.
  out.push_back(12);
  out.push_back(0); // IOAPIC ID.
  out.push_back(0); // Reserved.
  PutLe32(out, static_cast<uint32_t>(ioApicBase));
  PutLe32(out, 0); // GSI base.

  // Interrupt Source Override entries. Without these the guest assumes
  // identity mapping (ISA IRQ N -> GSI N) and inherits the ISA defaults
  // (edge / active high) for every line. The standard PC-AT topology that
  // bootmgfw/winload/the Windows kernel actually expect on a PIIX4 board
  // remaps the legacy PIT off IRQ0 onto GSI 2 (because GSI 0 is wired to
  // LINT0 for SMP NMI delivery) and rewires the SCI on IRQ 9 as
  // active-low / level-triggered. We emit both so the guest's ACPI
  // initialisation does not fall back to "8259 only" mode and start
  // masking everything.
  out.push_back(2); // Interrupt Source Override (PIT IRQ0 -> GSI 2).
  out.push_back(10);
  out.push_back(0);    // Bus: ISA.
  out.push_back(0);    // Source: ISA IRQ 0.
  PutLe32(out, 2);     // Global system interrupt.
  PutLe16(out, 0x0000); // Flags: conforms (defaults to edge / high on ISA).

  out.push_back(2); // Interrupt Source Override (SCI IRQ9 -> GSI 9, lvl/low).
  out.push_back(10);
  out.push_back(0);     // Bus: ISA.
  out.push_back(9);     // Source: ISA IRQ 9.
  PutLe32(out, 9);      // Global system interrupt.
  PutLe16(out, 0x000D); // Active-low (11b), level-triggered (11b).

  out.push_back(4); // Local APIC NMI.
  out.push_back(6);
  out.push_back(0xFF); // All processors.
  PutLe16(out, 0);     // Conforms.
  out.push_back(1);    // LINT1.

  EndSdt(out, offset);
  return offset;
}

uint32_t AppendWaet(std::vector<uint8_t> &out) {
  const auto offset = BeginSdt(out, "WAET", 1);
  PutLe32(out, 0x00000003u); // RTC and PM timer are good.
  EndSdt(out, offset);
  return offset;
}

uint32_t AppendHpet(std::vector<uint8_t> &out, uint64_t hpetBase) {
  const auto offset = BeginSdt(out, "HPET", 1);
  PutLe32(out, HpetDevice::kEventTimerBlockId);
  AppendGas(out, 0, 64, 0, 0, hpetBase);
  out.push_back(0);   // HPET sequence number.
  PutLe16(out, 0x80); // Minimum clock tick.
  out.push_back(0);   // Page protection: no guarantee.
  EndSdt(out, offset);
  return offset;
}

uint32_t AppendDbgp(std::vector<uint8_t> &out) {
  const auto offset = BeginSdt(out, "DBGP", 1);
  out.push_back(0); // Full 16550.
  out.insert(out.end(), 3, 0); // Reserved.
  AppendGas(out, 1, 8, 0, 0, 0x03F8);
  EndSdt(out, offset);
  return offset;
}

// TCG ACPI TPM2 table — published so OVMF's Tcg2Pei / Tcg2Dxe discovers the
// CRB MMIO control area at 0xFED40040 and exposes the EFI TCG2 protocol.
// Per TCG ACPI specification 1.4 §7 the layout after the standard ACPI
// header is:
//   uint16_t  PlatformClass       (0 = Client)
//   uint16_t  Reserved
//   uint64_t  AddressOfControlArea
//   uint32_t  StartMethod         (7 = CRB w/ ACPI Start)
//   uint8_t[] StartMethodSpecificParameters (12 bytes when StartMethod == 7)
//   uint32_t  LAML (log area min length)
//   uint64_t  LASA (log area start address)
uint32_t AppendTpm2(std::vector<uint8_t> &out, uint64_t controlAreaGpa,
                    uint32_t logAreaMinLength, uint64_t logAreaStartAddress) {
  const auto offset = BeginSdt(out, "TPM2", 4);
  PutLe16(out, 0);              // Platform Class: Client.
  PutLe16(out, 0);              // Reserved.
  PutLe64(out, controlAreaGpa); // Address of Control Area.
  PutLe32(out, 7);              // Start Method: CRB with ACPI Start.
  // Start-method-specific parameters (12 bytes for Start Method 7). All zero
  // for a vanilla CRB device — no special ACPI handoff bytes required.
  out.insert(out.end(), 12, 0);
  PutLe32(out, logAreaMinLength);   // LAML — TPM event log size.
  PutLe64(out, logAreaStartAddress); // LASA — TPM event log GPA.
  EndSdt(out, offset);
  return offset;
}

uint32_t AppendSpcr(std::vector<uint8_t> &out) {
  constexpr char kCom1Namespace[] = "\\_SB_.COM1";
  constexpr uint16_t kNamespaceOffset = 88;

  const auto offset = BeginSdt(out, "SPCR", 4);
  out.push_back(0); // Full 16550 / legacy COM-port compatible.
  out.insert(out.end(), 3, 0); // Reserved.
  AppendGas(out, 1, 8, 0, 0, 0x03F8); // System I/O COM1, per SPCR examples.
  out.push_back(0x03); // PC-AT IRQ + IOAPIC GSI.
  out.push_back(4);    // COM1 legacy IRQ.
  PutLe32(out, 4);     // COM1 GSI.
  out.push_back(7);    // 115200 baud.
  out.push_back(0);    // No parity.
  out.push_back(1);    // One stop bit.
  out.push_back(0);    // No flow control.
  out.push_back(2);    // VT-UTF8.
  out.push_back(0);    // Language.
  PutLe16(out, 0xFFFF); // Not PCI-backed.
  PutLe16(out, 0xFFFF); // Not PCI-backed.
  out.push_back(0);     // PCI bus.
  out.push_back(0);     // PCI device.
  out.push_back(0);     // PCI function.
  PutLe32(out, 0);      // PCI flags.
  out.push_back(0);     // PCI segment.
  PutLe32(out, 0);      // UART clock indeterminate.
  PutLe32(out, 0);      // Use configured baud enum.
  PutLe16(out, static_cast<uint16_t>(sizeof(kCom1Namespace)));
  PutLe16(out, kNamespaceOffset);
  out.insert(out.end(), kCom1Namespace,
             kCom1Namespace + sizeof(kCom1Namespace));
  EndSdt(out, offset);
  return offset;
}

uint32_t AppendDbg2(std::vector<uint8_t> &out) {
  constexpr char kCom1Namespace[] = "\\_SB_.COM1";
  constexpr uint32_t kDeviceInfoOffset = 44;
  constexpr uint16_t kBaseAddressOffset = 22;
  constexpr uint16_t kAddressSizeOffset = kBaseAddressOffset + 12;
  constexpr uint16_t kNamespaceOffset = kAddressSizeOffset + 4;
  constexpr uint16_t kDeviceInfoLength =
      kNamespaceOffset + static_cast<uint16_t>(sizeof(kCom1Namespace));

  const auto offset = BeginSdt(out, "DBG2", 0);
  PutLe32(out, kDeviceInfoOffset);
  PutLe32(out, 1); // One debug device: COM1.

  out.push_back(0); // Debug Device Information revision.
  PutLe16(out, kDeviceInfoLength);
  out.push_back(1); // One GAS register.
  PutLe16(out, static_cast<uint16_t>(sizeof(kCom1Namespace)));
  PutLe16(out, kNamespaceOffset);
  PutLe16(out, 0); // OEM data length.
  PutLe16(out, 0); // OEM data offset.
  PutLe16(out, 0x8000); // Serial debug port.
  PutLe16(out, 0x0001); // DBGP-compatible 16550 subset.
  PutLe16(out, 0);      // Reserved.
  PutLe16(out, kBaseAddressOffset);
  PutLe16(out, kAddressSizeOffset);
  AppendGas(out, 1, 8, 0, 1, 0x03F8);
  PutLe32(out, 8); // COM1 register window size.
  out.insert(out.end(), kCom1Namespace,
             kCom1Namespace + sizeof(kCom1Namespace));
  EndSdt(out, offset);
  return offset;
}

uint32_t AppendRsdt(std::vector<uint8_t> &out,
                    const std::vector<uint32_t> &tableOffsets) {
  const auto offset = BeginSdt(out, "RSDT", 1);
  for (uint32_t tableOffset : tableOffsets) {
    PutLe32(out, tableOffset);
  }
  EndSdt(out, offset);
  return offset;
}

// XSDT: the ACPI 2.0+ root table with 64-bit entry pointers. Modern Windows
// (and OVMF's table installer) iterate the XSDT, not the legacy RSDT, so this
// is required for the guest to discover the MADT/FADT/etc. Entry values are
// written as the in-blob offsets and relocated to runtime addresses by the
// table-loader's ADD_POINTER commands (size 8).
uint32_t AppendXsdt(std::vector<uint8_t> &out,
                    const std::vector<uint32_t> &tableOffsets) {
  const auto offset = BeginSdt(out, "XSDT", 1);
  for (uint32_t tableOffset : tableOffsets) {
    PutLe64(out, tableOffset);
  }
  EndSdt(out, offset);
  return offset;
}

void AppendLoaderName(std::vector<uint8_t> &entry, const char *name) {
  const size_t start = entry.size();
  entry.resize(start + 56, 0);
  const size_t n = std::min<size_t>(std::strlen(name), 55);
  std::memcpy(entry.data() + start, name, n);
}

void AppendLoaderEntry(std::vector<uint8_t> &out,
                       const std::vector<uint8_t> &entry) {
  if (entry.size() > 128) {
    throw std::runtime_error("table-loader entry too large");
  }
  out.insert(out.end(), entry.begin(), entry.end());
  out.insert(out.end(), 128 - entry.size(), 0);
}

void LoaderAllocate(std::vector<uint8_t> &out, const char *file,
                    uint32_t align, uint8_t zone) {
  std::vector<uint8_t> entry;
  PutLe32(entry, 1);
  AppendLoaderName(entry, file);
  PutLe32(entry, align);
  entry.push_back(zone);
  AppendLoaderEntry(out, entry);
}

void LoaderAddPointer(std::vector<uint8_t> &out, const char *destFile,
                      const char *srcFile, uint32_t offset, uint8_t size) {
  std::vector<uint8_t> entry;
  PutLe32(entry, 2);
  AppendLoaderName(entry, destFile);
  AppendLoaderName(entry, srcFile);
  PutLe32(entry, offset);
  entry.push_back(size);
  AppendLoaderEntry(out, entry);
}

void LoaderAddChecksum(std::vector<uint8_t> &out, const char *file,
                       uint32_t offset, uint32_t start, uint32_t length) {
  std::vector<uint8_t> entry;
  PutLe32(entry, 3);
  AppendLoaderName(entry, file);
  PutLe32(entry, offset);
  PutLe32(entry, start);
  PutLe32(entry, length);
  AppendLoaderEntry(out, entry);
}

std::vector<uint8_t> BuildRsdp(uint32_t rsdtOffset, uint32_t xsdtOffset) {
  std::vector<uint8_t> out;
  AppendFixedAscii(out, "RSD PTR ", 8, '\0'); // 0..7  signature
  out.push_back(0);                  // 8      checksum (loader recomputes)
  AppendFixedAscii(out, "ALASKA", 6); // 9..14  OEMID (anti-evasion: real-PC OEM)
  out.push_back(2);                  // 15     revision = ACPI 2.0+
  PutLe32(out, rsdtOffset);          // 16..19 RsdtAddress (loader relocates)
  PutLe32(out, 36);                  // 20..23 Length
  PutLe64(out, xsdtOffset);          // 24..31 XsdtAddress (loader relocates)
  out.push_back(0);                  // 32     ExtendedChecksum (loader recomputes)
  out.insert(out.end(), 3, 0);       // 33..35 reserved
  // Leave both RSDP checksums ZERO -- the table-loader's ADD_CHECKSUM commands
  // (offset 8 over 20 bytes; offset 32 over 36 bytes) fill them at load time,
  // and only yield valid sums if the bytes are 0 beforehand (see EndSdt).
  out[8] = 0;
  out[32] = 0;
  return out;
}

std::vector<uint8_t> BuildTableLoader(const AcpiTableOffsets &offsets,
                                      const std::vector<uint8_t> &tables,
                                      const std::vector<uint8_t> &rsdp) {
  std::vector<uint8_t> out;
  LoaderAllocate(out, kAcpiTablesFile, 64, kLoaderZoneFseg);
  LoaderAllocate(out, kRsdpFile, 16, kLoaderZoneFseg);

  LoaderAddPointer(out, kRsdpFile, kAcpiTablesFile, 16, 4);  // RSDP RsdtAddress
  LoaderAddPointer(out, kRsdpFile, kAcpiTablesFile, 24, 8);  // RSDP XsdtAddress
  LoaderAddPointer(out, kAcpiTablesFile, kAcpiTablesFile, offsets.fadt + 36, 4);
  LoaderAddPointer(out, kAcpiTablesFile, kAcpiTablesFile, offsets.fadt + 40, 4);
  // The 64-bit X_FirmwareCtrl / X_Dsdt pointers (offsets 132 / 140) MUST be
  // relocated too -- modern OVMF and Windows prefer the X_ fields over the
  // 32-bit FirmwareCtrl/Dsdt. Leaving them as raw blob offsets makes OVMF read
  // a garbage DSDT pointer and abort table installation after only the FADT
  // ("installed 1 tables"), so the MADT/APIC never reaches the guest.
  LoaderAddPointer(out, kAcpiTablesFile, kAcpiTablesFile, offsets.fadt + 132, 8);
  LoaderAddPointer(out, kAcpiTablesFile, kAcpiTablesFile, offsets.fadt + 140, 8);
  const uint32_t rsdtLength = AcpiTableLength(tables, offsets.rsdt);
  for (uint32_t entryOffset = 36; entryOffset + 4 <= rsdtLength;
       entryOffset += 4) {
    LoaderAddPointer(out, kAcpiTablesFile, kAcpiTablesFile,
                     offsets.rsdt + entryOffset, 4);
  }
  // Relocate the XSDT's 64-bit entry pointers (the table list Windows uses).
  const uint32_t xsdtLength = AcpiTableLength(tables, offsets.xsdt);
  for (uint32_t entryOffset = 36; entryOffset + 8 <= xsdtLength;
       entryOffset += 8) {
    LoaderAddPointer(out, kAcpiTablesFile, kAcpiTablesFile,
                     offsets.xsdt + entryOffset, 8);
  }

  LoaderAddChecksum(out, kAcpiTablesFile, offsets.dsdt + 9, offsets.dsdt,
                    AcpiTableLength(tables, offsets.dsdt));
  LoaderAddChecksum(out, kAcpiTablesFile, offsets.fadt + 9, offsets.fadt,
                    AcpiTableLength(tables, offsets.fadt));
  LoaderAddChecksum(out, kAcpiTablesFile, offsets.madt + 9, offsets.madt,
                    AcpiTableLength(tables, offsets.madt));
  LoaderAddChecksum(out, kAcpiTablesFile, offsets.waet + 9, offsets.waet,
                    AcpiTableLength(tables, offsets.waet));
  LoaderAddChecksum(out, kAcpiTablesFile, offsets.hpet + 9, offsets.hpet,
                    AcpiTableLength(tables, offsets.hpet));
  if (offsets.dbgp != 0) {
    LoaderAddChecksum(out, kAcpiTablesFile, offsets.dbgp + 9, offsets.dbgp,
                      AcpiTableLength(tables, offsets.dbgp));
  }
  LoaderAddChecksum(out, kAcpiTablesFile, offsets.spcr + 9, offsets.spcr,
                    AcpiTableLength(tables, offsets.spcr));
  LoaderAddChecksum(out, kAcpiTablesFile, offsets.dbg2 + 9, offsets.dbg2,
                    AcpiTableLength(tables, offsets.dbg2));
  if (offsets.tpm2 != 0) {
    LoaderAddChecksum(out, kAcpiTablesFile, offsets.tpm2 + 9, offsets.tpm2,
                      AcpiTableLength(tables, offsets.tpm2));
  }
  LoaderAddChecksum(out, kAcpiTablesFile, offsets.rsdt + 9, offsets.rsdt,
                    AcpiTableLength(tables, offsets.rsdt));
  LoaderAddChecksum(out, kAcpiTablesFile, offsets.xsdt + 9, offsets.xsdt,
                    AcpiTableLength(tables, offsets.xsdt));
  LoaderAddChecksum(out, kRsdpFile, 8, 0, 20);   // ACPI 1.0 checksum (first 20)
  LoaderAddChecksum(out, kRsdpFile, 32, 0, 36);  // ACPI 2.0 extended checksum
  return out;
}

} // namespace

uint32_t AcpiEisaId(const char id[8]) {
  const auto hex = [](char c) -> uint32_t {
    if (c >= '0' && c <= '9') {
      return static_cast<uint32_t>(c - '0');
    }
    if (c >= 'A' && c <= 'F') {
      return static_cast<uint32_t>(10 + c - 'A');
    }
    if (c >= 'a' && c <= 'f') {
      return static_cast<uint32_t>(10 + c - 'a');
    }
    return 0;
  };
  // ACPI _HID EISAID layout (ACPI spec 6.1.5): the 3-letter vendor is
  // bit-packed into the LOW two bytes and the 4-hex product ID into the HIGH
  // two bytes, so the little-endian DWORD's bytes read back as
  // [vendor0, vendor1, productHi, productLo] -- exactly what the OS ACPI
  // decoder expects. "PNP0A03" -> 0x030AD041.
  //
  // The previous code packed the vendor into the HIGH bits (vendor<<16..26 |
  // product), yielding 0x41D00A03, whose bytes decode to garbage "@XJD041".
  // Result: the OS never recognized PNP0A03 as the PCI root, pci.sys never
  // enumerated the PCI bus, the IDE controller was never created as a PnP
  // device, the boot disk never appeared -> INACCESSIBLE_BOOT_DEVICE (0x7B).
  const uint32_t c1 = static_cast<uint32_t>(id[0] - '@') & 0x1Fu;
  const uint32_t c2 = static_cast<uint32_t>(id[1] - '@') & 0x1Fu;
  const uint32_t c3 = static_cast<uint32_t>(id[2] - '@') & 0x1Fu;
  const uint32_t b0 = (c1 << 2) | (c2 >> 3);
  const uint32_t b1 = ((c2 & 0x7u) << 5) | c3;
  const uint32_t b2 = (hex(id[3]) << 4) | hex(id[4]);
  const uint32_t b3 = (hex(id[5]) << 4) | hex(id[6]);
  return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
}

bool AcpiChecksumValid(const uint8_t *bytes, size_t size) {
  if (!bytes || size == 0) {
    return false;
  }
  uint8_t sum = 0;
  for (size_t i = 0; i < size; ++i) {
    sum = static_cast<uint8_t>(sum + bytes[i]);
  }
  return sum == 0;
}

uint32_t AcpiTableLength(const std::vector<uint8_t> &blob, uint32_t offset) {
  if (offset + 8 > blob.size()) {
    return 0;
  }
  return static_cast<uint32_t>(blob[offset + 4]) |
         (static_cast<uint32_t>(blob[offset + 5]) << 8) |
         (static_cast<uint32_t>(blob[offset + 6]) << 16) |
         (static_cast<uint32_t>(blob[offset + 7]) << 24);
}

AcpiBuildArtifacts BuildPcAcpiTables(uint32_t processorCount, bool includeDbgp,
                                     uint32_t tpmEventLogSize,
                                     uint64_t tpmEventLogGpa,
                                     uint64_t ioApicBase,
                                     uint64_t hpetBase,
                                     uint64_t tpmCrbBase,
                                     bool includeTpm2) {
  AcpiBuildArtifacts artifacts;
  auto &tables = artifacts.tables;
  artifacts.offsets.facs = AppendFacs(tables);
  artifacts.offsets.dsdt = AppendDsdt(tables, processorCount);
  artifacts.offsets.fadt =
      AppendFadt(tables, artifacts.offsets.facs, artifacts.offsets.dsdt);
  artifacts.offsets.madt = AppendMadt(tables, processorCount, ioApicBase);
  artifacts.offsets.waet = AppendWaet(tables);
  artifacts.offsets.hpet = AppendHpet(tables, hpetBase);
  if (includeDbgp) {
    artifacts.offsets.dbgp = AppendDbgp(tables);
  }
  artifacts.offsets.spcr = AppendSpcr(tables);
  artifacts.offsets.dbg2 = AppendDbg2(tables);
  // TPM 2.0 ACPI table — points OVMF's Tcg2Pei/Tcg2Dxe at our CRB stub.
  // When includeTpm2 is false we omit the table entirely so that neither
  // firmware nor the OS attempts to use a TPM that WHP's LAPIC emulation
  // makes unreachable (dummy pages absorb all MMIO accesses in the
  // [0xFEC00000, 0xFEF00000) range). Without a TPM2 ACPI table, winload's
  // SpacebootInitialize skips the measured-boot path that was returning
  // STATUS_ILLEGAL_FUNCTION (0xC00000B9).
  if (includeTpm2) {
    artifacts.offsets.tpm2 = AppendTpm2(
        tables,
        tpmCrbBase + Tpm2CrbDevice::kControlAreaOffset,
        tpmEventLogSize, tpmEventLogGpa);
  }
  // Build RSDT with all present tables.
  std::vector<uint32_t> rsdtEntries = {
      artifacts.offsets.fadt, artifacts.offsets.madt,
      artifacts.offsets.waet, artifacts.offsets.hpet};
  if (includeDbgp) {
    rsdtEntries.push_back(artifacts.offsets.dbgp);
  }
  rsdtEntries.push_back(artifacts.offsets.spcr);
  rsdtEntries.push_back(artifacts.offsets.dbg2);
  if (artifacts.offsets.tpm2 != 0) {
    rsdtEntries.push_back(artifacts.offsets.tpm2);
  }
  artifacts.offsets.rsdt = AppendRsdt(tables, rsdtEntries);
  artifacts.offsets.xsdt = AppendXsdt(tables, rsdtEntries);

  artifacts.rsdp =
      BuildRsdp(artifacts.offsets.rsdt, artifacts.offsets.xsdt);
  artifacts.tableLoader =
      BuildTableLoader(artifacts.offsets, artifacts.tables, artifacts.rsdp);
  return artifacts;
}

} // namespace antimal::hv
