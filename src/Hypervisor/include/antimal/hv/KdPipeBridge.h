#pragma once

// Bridges the guest's KD serial port (COM1) to a Windows named pipe so a real
// kernel debugger can drive the session:
//
//   kd.exe -k com:pipe,port=\\.\pipe\antimal-kd,resets=0,reconnect
//
// The in-house KdSerialDebugger is observational (it auto-ACKs and loops the
// handshake); this bridge instead hands the raw KD byte stream to WinDbg/kd,
// which does the real protocol (break-in, !process, ~*k, symbols).
//
// I/O model: the VM run loop calls Pump() once per iteration to do ALL pipe
// data I/O inline (non-blocking PeekNamedPipe + ReadFile for debugger->guest, a
// direct WriteFile for guest->debugger). This is deliberate. An earlier design
// used CV-woken reader/writer worker threads, but the cross-thread hand-off
// delayed delivery of the debugger's ACKs past the kernel's KdReceivePacket
// retry window, so the kernel re-sent its STATE_CHANGE break-notification
// forever and the session never converged (kd stuck at "no_debuggee" /
// "Unable to read head of debugger data list, 0n56"). Pumping in the run loop
// delivers the debugger's bytes to COM1 the same iteration the kernel polls for
// them, with no scheduling lag. A single tiny accept thread owns only the
// blocking ConnectNamedPipe (so the run loop never blocks waiting for kd to
// attach) and re-listens on disconnect for attach/detach.

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <Windows.h>

namespace antimal::hv {

class KdPipeBridge {
public:
  explicit KdPipeBridge(const std::wstring &pipeName);
  ~KdPipeBridge();

  KdPipeBridge(const KdPipeBridge &) = delete;
  KdPipeBridge &operator=(const KdPipeBridge &) = delete;

  bool Valid() const noexcept { return pipe_ != INVALID_HANDLE_VALUE; }
  bool ClientConnected() const noexcept {
    return connected_.load(std::memory_order_relaxed);
  }

  // Guest wrote these bytes to COM1 (guest -> debugger). Queued; flushed by Pump.
  void SendToDebugger(const uint8_t *data, size_t size);
  // Bytes the debugger sent (debugger -> guest); feed these to COM1 RX. Filled
  // by Pump(); drain right after calling Pump().
  std::vector<uint8_t> ReceiveFromDebugger();

  // Drive all pipe data I/O inline from the VM run loop: pull any available
  // debugger->guest bytes (non-blocking, PeekNamedPipe-gated) and flush queued
  // guest->debugger bytes. Never blocks. Call once per run-loop iteration.
  void Pump();

  uint64_t BytesToDebugger() const noexcept {
    return bytesToDbg_.load(std::memory_order_relaxed);
  }
  uint64_t BytesFromDebugger() const noexcept {
    return bytesFromDbg_.load(std::memory_order_relaxed);
  }
  uint64_t ClientConnects() const noexcept {
    return clientConnects_.load(std::memory_order_relaxed);
  }

private:
  void AcceptProc();
  void SignalReaccept();

  // Diagnostics: when ANTIMAL_KD_DUMP is set, append the raw bidirectional KD
  // byte stream to _to_dbg.bin (guest->debugger) and _from_dbg.bin
  // (debugger->guest) so the framing/checksum can be decoded offline.
  HANDLE dumpTo_ = INVALID_HANDLE_VALUE;   // guest -> debugger
  HANDLE dumpFrom_ = INVALID_HANDLE_VALUE; // debugger -> guest

  // Drop oldest queued guest->debugger bytes past this cap while no client is
  // attached (kd resyncs on connect, so stale retries are safe to discard).
  static constexpr size_t kMaxTxQueue = 256u * 1024u;

  HANDLE pipe_ = INVALID_HANDLE_VALUE;
  std::atomic_bool stop_{false};
  std::atomic_bool connected_{false};
  std::atomic<uint64_t> bytesToDbg_{0};
  std::atomic<uint64_t> bytesFromDbg_{0};
  std::atomic<uint64_t> clientConnects_{0};

  std::mutex txMu_;
  std::deque<uint8_t> tx_; // guest -> debugger (flushed by Pump)

  std::mutex rxMu_;
  std::deque<uint8_t> rx_; // debugger -> guest (filled by Pump)

  // The accept thread owns ONLY the blocking ConnectNamedPipe + re-listen, so
  // the run loop never blocks waiting for kd. All data I/O is in Pump().
  std::thread accept_;
  std::mutex acceptMu_;
  std::condition_variable acceptCv_;
  bool needReaccept_ = false;
};

} // namespace antimal::hv
