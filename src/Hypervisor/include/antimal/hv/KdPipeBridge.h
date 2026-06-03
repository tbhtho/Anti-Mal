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
// A worker owns the blocking pipe I/O so the VM run loop never blocks: the loop
// only enqueues guest->debugger bytes and drains debugger->guest bytes. Two
// threads share the full-duplex pipe handle (one read, one write).

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

  // Guest wrote these bytes to COM1 (guest -> debugger). Queued for the writer.
  void SendToDebugger(const uint8_t *data, size_t size);
  // Bytes the debugger sent (debugger -> guest); feed these to COM1 RX.
  std::vector<uint8_t> ReceiveFromDebugger();

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
  void ReaderProc();
  void WriterProc();

  // Diagnostics: when ANTIMAL_KD_DUMP is set, append the raw bidirectional KD
  // byte stream to <value>_to_dbg.bin (guest->debugger) and <value>_from_dbg.bin
  // (debugger->guest) so the framing/checksum can be decoded offline. The two
  // files are written by different threads (VM loop vs reader), so each gets its
  // own handle and no lock is shared between directions.
  HANDLE dumpTo_ = INVALID_HANDLE_VALUE;   // guest -> debugger
  HANDLE dumpFrom_ = INVALID_HANDLE_VALUE; // debugger -> guest

  // Drop oldest queued guest->debugger bytes past this cap while no client is
  // attached (the guest resends KD state; WinDbg resyncs on connect, so stale
  // retries are safe to discard rather than buffering unboundedly).
  static constexpr size_t kMaxTxQueue = 256u * 1024u;

  HANDLE pipe_ = INVALID_HANDLE_VALUE;
  std::atomic_bool stop_{false};
  std::atomic_bool connected_{false};
  std::atomic<uint64_t> bytesToDbg_{0};
  std::atomic<uint64_t> bytesFromDbg_{0};
  std::atomic<uint64_t> clientConnects_{0};

  std::mutex txMu_;
  std::condition_variable txCv_;
  std::deque<uint8_t> tx_; // guest -> debugger

  std::mutex rxMu_;
  std::deque<uint8_t> rx_; // debugger -> guest

  std::thread reader_;
  std::thread writer_;
};

} // namespace antimal::hv
