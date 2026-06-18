#pragma once

// Intel 82574L (e1000e) NIC, PCI device 8086:10D3. We target the e1000e family
// (inbox `e1d*.inf`, far longer Win11 lifetime than the old `e1000`/`8086:100E`
// whose `e1net*.inf` was dropped) so the in-guest driver actually binds, while
// reusing the existing 82540EM-family register layout (same TX/RX descriptor
// format + MDIC/PHY model). It presents as a real Intel desktop GbE NIC (no
// paravirt fingerprint). See historical design notes (not distributed).
//
// This is BOTH halves of contained network visibility:
//   * TX (capture): the guest transmits Ethernet frames through the TX descriptor
//     ring; we DMA them out to a host TX handler (PacketInspector + PCAP).
//   * RX (delivery): the host sink injects reply frames via DeliverRxFrame, which
//     fills the guest's RX descriptor ring — so DNS/TCP/HTTP replies arrive and
//     the guest stack exhibits real behavior, all with ZERO real egress.
//
// Scope today: PCI MMIO register block + EEPROM MAC + TX ring (DMA-assemble ->
// handler, TXDW int) + RX ring (host-driven DeliverRxFrame -> RXT0 int). The
// live driver-binding acceptance gate (`nicRegisterWrites > 0` on a real boot)
// is user-gated; the device + rings are unit-tested by driving them directly.
//
// SAFETY: RX descriptor parsing is untrusted-guest-pointer handling. Every
// descriptor field (buffer GPA, length) goes through the bounds-checked
// dmaMemory_ accessor and is length-clamped before any copy (see DeliverRxFrame).
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
  static constexpr uint16_t kPciDeviceId = 0x10D3;  // 82574L (e1000e)

  E1000Device();

  // Host pointer to [gpa, gpa+len) in guest RAM (wraps HostPointerForGpa), or
  // nullptr if unbacked. Used to read TX descriptors + frame buffers.
  using DmaMemoryFn = std::function<uint8_t *(uint64_t gpa, std::size_t len)>;
  void SetDmaMemory(DmaMemoryFn fn) { dmaMemory_ = std::move(fn); }

  // Called with each fully assembled outbound Ethernet frame.
  using TxFrameFn = std::function<void(const uint8_t *frame, std::size_t len)>;
  void SetTxHandler(TxFrameFn fn) { txHandler_ = std::move(fn); }

  // Deliver one inbound Ethernet frame INTO the guest by filling the next free
  // RX descriptor (host-driven; the guest only posts empty buffers by advancing
  // RDT). Returns true if the frame was placed in the ring, false if it was
  // dropped (RX disabled, no ring, no free buffer, or an unbacked descriptor).
  // Called by the host fake-internet sink — NEVER by the guest. The frame is
  // length-clamped to the RX buffer size and a hard 16 KiB cap before any copy.
  bool DeliverRxFrame(const uint8_t *frame, std::size_t len);

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
  uint64_t FramesReceived() const noexcept { return framesReceived_; }
  uint64_t BytesReceived() const noexcept { return bytesReceived_; }
  // Inbound frames dropped because the guest had no free RX descriptor / RX was
  // disabled / the descriptor was unbacked.
  uint64_t FramesDropped() const noexcept { return framesDropped_; }
  // Register writes by the guest driver — >0 means the e1000e driver bound and
  // touched the device (vs. never enumerated/bound). The Phase-1 acceptance gate.
  uint64_t RegisterWrites() const noexcept { return mmioWrites_; }

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
  uint32_t mdic_ = 0;  // MDI control (PHY register access)
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
  uint64_t framesReceived_ = 0;
  uint64_t bytesReceived_ = 0;
  uint64_t framesDropped_ = 0;
  uint64_t mmioWrites_ = 0;
};

}  // namespace antimal::hv
