#pragma once

// Minimal Intel 82093AA-style IOAPIC. Modern Windows kernels require either
// an IOAPIC (the normal case) or an ACPI flag explicitly putting the system
// in "8259 only" mode. OVMF always discovers our IOAPIC via the MADT entry
// the firmware builds when it sees the device at its conventional MMIO base
// of 0xFEC00000.
//
// The IOAPIC has a tiny MMIO surface:
//   0xFEC00000 + 0x00 : IOREGSEL (write the index of the register to access)
//   0xFEC00000 + 0x10 : IOWIN    (read/write the data of the selected register)
//
// Indirect register layout:
//   0x00      : IOAPICID
//   0x01      : IOAPICVER (low byte) + MAX_REDIR_ENTRY in bits 16..23
//   0x02      : IOAPICARB
//   0x10..0x3F: 24 redirection entries, two 32-bit slots each
//
// Each 64-bit redirection entry contains:
//   bits[7:0]   vector (CPU interrupt vector to deliver)
//   bits[10:8]  delivery mode (0 = fixed)
//   bit  11     destination mode (0 = physical APIC id)
//   bit  12     delivery status (read-only, always 0 in this stub)
//   bit  13     polarity (0 = active high)
//   bit  14     remote IRR (level-triggered EOI bookkeeping)
//   bit  15     trigger mode (0 = edge, 1 = level)
//   bit  16     mask
//   bits[55:32] reserved
//   bits[63:56] destination APIC id (0 for single-vCPU setups)

#include "antimal/hv/Device.h"

#include <array>
#include <cstdint>

namespace antimal::hv {

class IoApic final : public IMmioDevice {
public:
  static constexpr uint64_t kDefaultMmioBase = 0xFEC00000ull;
  static constexpr uint32_t kRedirectionEntries = 24;

  // Callback signature used to deliver a fixed interrupt vector to the right
  // virtual processor. Returning true means delivery was attempted (whether
  // it eventually arrives is a hypervisor-internal concern); false signals
  // delivery should be retried.
  using DeliverFn =
      bool (*)(void *context, uint32_t destination, uint8_t vector);

  explicit IoApic(uint64_t mmioBase = kDefaultMmioBase);

  void SetDeliveryCallback(DeliverFn callback, void *context) noexcept;

  // Asserts the given IRQ line on the IOAPIC. Looks up the redirection entry
  // and, if unmasked, delivers the configured vector to the configured CPU.
  // Returns true when delivery was attempted, false when the line is masked
  // or no callback is wired.
  bool RaiseIrq(uint8_t irq);

  uint64_t MmioBase() const noexcept override { return mmioBase_; }
  uint64_t MmioLast() const noexcept override { return mmioBase_ + 0xFFFull; }
  bool OnRead(uint64_t gpa, uint8_t accessSize, uint64_t *outValue) override;
  bool OnWrite(uint64_t gpa, uint8_t accessSize, uint64_t value) override;

  uint32_t IndirectRead(uint8_t index) const;
  void IndirectWrite(uint8_t index, uint32_t value);

  uint32_t IoApicId() const noexcept { return ioApicId_; }
  uint64_t RedirectionEntry(uint32_t i) const noexcept {
    return i < kRedirectionEntries ? redirection_[i] : 0;
  }

  // Diagnostic counters.
  uint64_t RaiseCount() const noexcept { return raiseCount_; }
  uint64_t MaskedDrops() const noexcept { return maskedDrops_; }
  uint64_t Deliveries() const noexcept { return deliveries_; }

private:
  uint64_t mmioBase_;
  uint32_t ioRegSel_ = 0;
  uint32_t ioApicId_ = 0;
  std::array<uint64_t, kRedirectionEntries> redirection_{};
  DeliverFn deliver_ = nullptr;
  void *deliverContext_ = nullptr;
  uint64_t raiseCount_ = 0;
  uint64_t maskedDrops_ = 0;
  uint64_t deliveries_ = 0;
};

} // namespace antimal::hv
