#include "antimal/hv/AcpiTables.h"

#include "antimal/hv/Hpet.h"

#include <algorithm>
#include <array>
#include <cstring>
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

uint8_t ChecksumByte(const uint8_t *bytes, size_t size) {
  uint8_t sum = 0;
  for (size_t i = 0; i < size; ++i) {
    sum = static_cast<uint8_t>(sum + bytes[i]);
  }
  return static_cast<uint8_t>(0u - sum);
}

uint32_t BeginSdt(std::vector<uint8_t> &out, std::string_view signature,
                  uint8_t revision) {
  const auto offset = static_cast<uint32_t>(out.size());
  AppendFixedAscii(out, signature, 4, '\0');
  PutLe32(out, 0); // Length patched by EndSdt.
  out.push_back(revision);
  out.push_back(0); // Checksum patched by EndSdt.
  AppendFixedAscii(out, "AMAL", 6);
  AppendFixedAscii(out, "ANTIMAL", 8);
  PutLe32(out, 1);
  AppendFixedAscii(out, "AMAL", 4);
  PutLe32(out, 1);
  return offset;
}

void EndSdt(std::vector<uint8_t> &out, uint32_t offset) {
  const uint32_t length = static_cast<uint32_t>(out.size() - offset);
  WriteLe32(out, offset + 4, length);
  out[offset + 9] = 0;
  out[offset + 9] = ChecksumByte(out.data() + offset, length);
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
  AppendName(pciTerms, "_PRT",
             PackageObject({PciRoutingEntry(1, 0, 14),
                            PciRoutingEntry(1, 1, 15),
                            PciRoutingEntry(2, 0, 10)}));

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
  auto appendGas = [&](uint8_t addressSpace, uint8_t bitWidth,
                       uint8_t bitOffset, uint8_t accessSize,
                       uint64_t address) {
    out.push_back(addressSpace);
    out.push_back(bitWidth);
    out.push_back(bitOffset);
    out.push_back(accessSize);
    PutLe64(out, address);
  };

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
  appendGas(1, 8, 0, 1, 0xCF9); // Reset register (I/O port).
  out.push_back(0x06);          // Reset value.
  out.insert(out.end(), 3, 0);  // Reserved.
  PutLe64(out, facsOffset);     // X_FirmwareCtrl.
  PutLe64(out, dsdtOffset);     // X_Dsdt.
  appendGas(1, 32, 0, 3, kPm1EventBlock);
  appendGas(1, 0, 0, 0, 0);
  appendGas(1, 16, 0, 2, kPm1ControlBlock);
  appendGas(1, 0, 0, 0, 0);
  appendGas(1, 0, 0, 0, 0);
  appendGas(1, 32, 0, 3, kPmTimerBlock);
  appendGas(1, 0, 0, 0, 0);
  appendGas(1, 0, 0, 0, 0);
  EndSdt(out, offset);
  return offset;
}

uint32_t AppendMadt(std::vector<uint8_t> &out, uint32_t processorCount) {
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
  PutLe32(out, 0xFEC00000u);
  PutLe32(out, 0); // GSI base.

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

uint32_t AppendHpet(std::vector<uint8_t> &out) {
  const auto offset = BeginSdt(out, "HPET", 1);
  PutLe32(out, HpetDevice::kEventTimerBlockId);
  out.push_back(0);  // GAS address space: system memory.
  out.push_back(64); // Register bit width.
  out.push_back(0);  // Register bit offset.
  out.push_back(0);  // Access size: undefined/legacy.
  PutLe64(out, HpetDevice::kDefaultMmioBase);
  out.push_back(0);   // HPET sequence number.
  PutLe16(out, 0x80); // Minimum clock tick.
  out.push_back(0);   // Page protection: no guarantee.
  EndSdt(out, offset);
  return offset;
}

uint32_t AppendRsdt(std::vector<uint8_t> &out,
                    const std::array<uint32_t, 4> &tableOffsets) {
  const auto offset = BeginSdt(out, "RSDT", 1);
  for (uint32_t tableOffset : tableOffsets) {
    PutLe32(out, tableOffset);
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

std::vector<uint8_t> BuildRsdp(uint32_t rsdtOffset) {
  std::vector<uint8_t> out;
  AppendFixedAscii(out, "RSD PTR ", 8, '\0');
  out.push_back(0); // Checksum patched by table-loader.
  AppendFixedAscii(out, "AMAL", 6);
  out.push_back(0); // ACPI 1.0 RSDP.
  PutLe32(out, rsdtOffset);
  out[8] = ChecksumByte(out.data(), out.size());
  return out;
}

std::vector<uint8_t> BuildTableLoader(const AcpiTableOffsets &offsets,
                                      const std::vector<uint8_t> &tables,
                                      const std::vector<uint8_t> &rsdp) {
  std::vector<uint8_t> out;
  LoaderAllocate(out, kAcpiTablesFile, 64, kLoaderZoneFseg);
  LoaderAllocate(out, kRsdpFile, 16, kLoaderZoneFseg);

  LoaderAddPointer(out, kRsdpFile, kAcpiTablesFile, 16, 4);
  LoaderAddPointer(out, kAcpiTablesFile, kAcpiTablesFile, offsets.fadt + 36, 4);
  LoaderAddPointer(out, kAcpiTablesFile, kAcpiTablesFile, offsets.fadt + 40, 4);
  LoaderAddPointer(out, kAcpiTablesFile, kAcpiTablesFile, offsets.rsdt + 36, 4);
  LoaderAddPointer(out, kAcpiTablesFile, kAcpiTablesFile, offsets.rsdt + 40, 4);
  LoaderAddPointer(out, kAcpiTablesFile, kAcpiTablesFile, offsets.rsdt + 44, 4);
  LoaderAddPointer(out, kAcpiTablesFile, kAcpiTablesFile, offsets.rsdt + 48, 4);

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
  LoaderAddChecksum(out, kAcpiTablesFile, offsets.rsdt + 9, offsets.rsdt,
                    AcpiTableLength(tables, offsets.rsdt));
  LoaderAddChecksum(out, kRsdpFile, 8, 0, 20);
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
  const uint32_t vendor =
      ((static_cast<uint32_t>(id[0] - '@') & 0x1Fu) << 26) |
      ((static_cast<uint32_t>(id[1] - '@') & 0x1Fu) << 21) |
      ((static_cast<uint32_t>(id[2] - '@') & 0x1Fu) << 16);
  const uint32_t product =
      (hex(id[3]) << 12) | (hex(id[4]) << 8) | (hex(id[5]) << 4) |
      hex(id[6]);
  return vendor | product;
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

AcpiBuildArtifacts BuildPcAcpiTables(uint32_t processorCount) {
  AcpiBuildArtifacts artifacts;
  auto &tables = artifacts.tables;
  artifacts.offsets.facs = AppendFacs(tables);
  artifacts.offsets.dsdt = AppendDsdt(tables, processorCount);
  artifacts.offsets.fadt =
      AppendFadt(tables, artifacts.offsets.facs, artifacts.offsets.dsdt);
  artifacts.offsets.madt = AppendMadt(tables, processorCount);
  artifacts.offsets.waet = AppendWaet(tables);
  artifacts.offsets.hpet = AppendHpet(tables);
  artifacts.offsets.rsdt =
      AppendRsdt(tables, {artifacts.offsets.fadt, artifacts.offsets.madt,
                          artifacts.offsets.waet, artifacts.offsets.hpet});

  artifacts.rsdp = BuildRsdp(artifacts.offsets.rsdt);
  artifacts.tableLoader =
      BuildTableLoader(artifacts.offsets, artifacts.tables, artifacts.rsdp);
  return artifacts;
}

} // namespace antimal::hv
