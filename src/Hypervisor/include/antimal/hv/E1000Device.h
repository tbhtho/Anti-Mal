#pragma once

// Minimal Intel 82540EM (e1000) NIC, PCI device 8086:100E — the most broadly
// driver-supported emulated NIC. This is the *capture* half of network-request
// visibility (SP3): the guest's network stack transmits Ethernet frames through
// the e1000 TX descriptor ring, and we DMA them out and hand each to a host TX
// handler (which runs the PacketInspector + records a PCAP). Outbound capture in
// containment is exactly what a malware sandbox wants — see the requests without
// granting real internet.
//
// Scope today: PCI MMIO register block + EEPROM MAC + the TX descriptor ring
// (DMA-assemble frames -> TX handler, TXDW interrupt). RX / fake-internet
// responses and live driver-binding validation are the remaining (live-iterated)
// work; this TX core is unit-tested by driving the registers directly.
//
// Register subset (BAR0 MMIO):
//   CTRL 0x0000, STATUS 0x0008, EERD 0x0014, ICR 0x00C0, IMS 0x00D0, IMC 0x00D8,
//   RCTL 0x0100, TCTL 0x0400, TDBAL 0x3800, TDBAH 0x3804, TDLEN 0x3808,
//   TDH 0x3810, TDT 0x3818, RAL 0x5400, RAH 0x5404.

#include "antimal/hv/Device.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>

namespace antimal::hv {

class E1000Device final : public IMmioDevice {
 public:
  static constexpr uint64_t kBarSize = 0x20000;  // 128 KiB register space
  static constexpr uint16_t kPciVendorId = 0x8086;
  static constexpr uint16_t kPciDeviceId = 0x100E;  // 82540EM

  E1000Device();

  // Host pointer to [gpa, gpa+len) in guest RAM (wraps HostPointerForGpa), or
  // nullptr if unbacked. Used to read TX descriptors + frame buffers.
  using DmaMemoryFn = std::function<uint8_t *(uint64_t gpa, std::size_t len)>;
  void SetDmaMemory(DmaMemoryFn fn) { dmaMemory_ = std::move(fn); }

  // Called with each fully assembled outbound Ethernet frame.
  using TxFrameFn = std::function<void(const uint8_t *frame, std::size_t len)>;
  void SetTxHandler(TxFrameFn fn) { txHandler_ = std::move(fn); }

  // BAR0 base, latched from the guest's PCI BAR assignment (like AHCI's ABAR).
  void SetMmioBase(uint64_t base) noexcept { mmioBase_ = base & ~0xFULL; }
  uint64_t MmioBaseAddr() const noexcept { return mmioBase_; }

  // IMmioDevice.
  uint64_t MmioBase() const noexcept override { return mmioBase_; }
  uint64_t MmioLast() const noexcept override {
    return mmioBase_ + kBarSize - 1;
  }
  bool OnRead(uint64_t gpa, uint8_t accessSize, uint64_t *outValue) override;
  bool OnWrite(uint64_t gpa, uint8_t accessSize, uint64_t value) override;

  // PCI INTx latch, polled by the host run loop (like AhciController).
  bool InterruptPending() const noexcept { return interruptPending_; }
  bool ConsumeInterrupt() noexcept {
    const bool p = interruptPending_;
    interruptPending_ = false;
    return p;
  }

  // Power-on register state for a guest reboot (keeps the MAC + DMA/handler).
  void Reset() noexcept;

  // Diagnostics.
  uint64_t FramesTransmitted() const noexcept { return framesTransmitted_; }
  uint64_t BytesTransmitted() const noexcept { return bytesTransmitted_; }

 private:
  void WriteReg(uint32_t off, uint32_t value);
  uint32_t ReadReg(uint32_t off);
  void ProcessTx();  // walk TDH..TDT, DMA-assemble frames, call the handler.

  DmaMemoryFn dmaMemory_;
  TxFrameFn txHandler_;
  uint64_t mmioBase_ = 0;

  std::array<uint16_t, 64> eeprom_{};  // word 0..2 = MAC
  uint32_t ctrl_ = 0;
  uint32_t eerd_ = 0;
  uint32_t icr_ = 0;
  uint32_t ims_ = 0;
  uint32_t tctl_ = 0;
  uint32_t tdbal_ = 0, tdbah_ = 0, tdlen_ = 0, tdh_ = 0, tdt_ = 0;
  // RX ring registers. We never deliver inbound packets (contained sandbox), but
  // the driver sets up the RX ring during init and reads these back; storing
  // them lets RX init complete so the driver starts and proceeds to TX.
  uint32_t rctl_ = 0;
  uint32_t rdbal_ = 0, rdbah_ = 0, rdlen_ = 0, rdh_ = 0, rdt_ = 0;
  uint32_t ral_ = 0, rah_ = 0;
  bool linkAnnounced_ = false;  // raised one Link-Status-Change interrupt yet
  bool interruptPending_ = false;

  uint64_t framesTransmitted_ = 0;
  uint64_t bytesTransmitted_ = 0;
};

}  // namespace antimal::hv
