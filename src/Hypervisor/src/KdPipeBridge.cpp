#include "antimal/hv/KdPipeBridge.h"

#include <cstdlib>

namespace antimal::hv {

namespace {
void AppendBytes(HANDLE h, const uint8_t *data, size_t size) {
  if (h == INVALID_HANDLE_VALUE || !data || size == 0) {
    return;
  }
  size_t off = 0;
  while (off < size) {
    DWORD wrote = 0;
    if (!WriteFile(h, data + off, static_cast<DWORD>(size - off), &wrote,
                   nullptr) ||
        wrote == 0) {
      break;
    }
    off += wrote;
  }
}
} // namespace

KdPipeBridge::KdPipeBridge(const std::wstring &pipeName) {
  pipe_ = CreateNamedPipeW(
      pipeName.c_str(), PIPE_ACCESS_DUPLEX,
      PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
      1,                  // one instance (one debugger)
      64u * 1024u,        // out buffer
      64u * 1024u,        // in buffer
      0, nullptr);
  if (pipe_ == INVALID_HANDLE_VALUE) {
    return;
  }
  // Optional raw-stream capture for offline KD-packet decoding.
  size_t dumpLen = 0;
  char dumpVal[8] = {0};
  if (getenv_s(&dumpLen, dumpVal, sizeof(dumpVal), "ANTIMAL_KD_DUMP") == 0 &&
      dumpLen > 0) {
    dumpTo_ = CreateFileW(L"C:\\AntiMalRuns\\_kddump_to_dbg.bin", GENERIC_WRITE,
                          FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                          FILE_ATTRIBUTE_NORMAL, nullptr);
    dumpFrom_ =
        CreateFileW(L"C:\\AntiMalRuns\\_kddump_from_dbg.bin", GENERIC_WRITE,
                    FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, nullptr);
  }
  // Only the blocking ConnectNamedPipe (+ re-listen) lives on a thread; all data
  // I/O is driven inline by Pump() from the run loop.
  accept_ = std::thread([this] { AcceptProc(); });
}

KdPipeBridge::~KdPipeBridge() {
  stop_.store(true, std::memory_order_relaxed);
  {
    std::lock_guard<std::mutex> lk(acceptMu_);
    needReaccept_ = true;
  }
  acceptCv_.notify_all();
  if (pipe_ != INVALID_HANDLE_VALUE) {
    // Unblock any in-flight ConnectNamedPipe in AcceptProc.
    CancelIoEx(pipe_, nullptr);
  }
  if (accept_.joinable()) {
    accept_.join();
  }
  if (pipe_ != INVALID_HANDLE_VALUE) {
    DisconnectNamedPipe(pipe_);
    CloseHandle(pipe_);
    pipe_ = INVALID_HANDLE_VALUE;
  }
  if (dumpTo_ != INVALID_HANDLE_VALUE) {
    CloseHandle(dumpTo_);
    dumpTo_ = INVALID_HANDLE_VALUE;
  }
  if (dumpFrom_ != INVALID_HANDLE_VALUE) {
    CloseHandle(dumpFrom_);
    dumpFrom_ = INVALID_HANDLE_VALUE;
  }
}

void KdPipeBridge::SendToDebugger(const uint8_t *data, size_t size) {
  if (!data || size == 0 || pipe_ == INVALID_HANDLE_VALUE) {
    return;
  }
  AppendBytes(dumpTo_, data, size);
  std::lock_guard<std::mutex> lock(txMu_);
  tx_.insert(tx_.end(), data, data + size);
  // While no client is attached, bound the backlog (drop oldest). We do NOT
  // clear tx_ on disconnect: kd resyncs via reconnect churn and the not-yet-
  // sent bytes are the kernel's in-flight packet it still needs delivered.
  if (!connected_.load(std::memory_order_relaxed) && tx_.size() > kMaxTxQueue) {
    tx_.erase(tx_.begin(),
              tx_.begin() +
                  static_cast<std::ptrdiff_t>(tx_.size() - kMaxTxQueue));
  }
}

std::vector<uint8_t> KdPipeBridge::ReceiveFromDebugger() {
  std::vector<uint8_t> out;
  std::lock_guard<std::mutex> lock(rxMu_);
  if (!rx_.empty()) {
    out.assign(rx_.begin(), rx_.end());
    rx_.clear();
  }
  return out;
}

void KdPipeBridge::SignalReaccept() {
  connected_.store(false, std::memory_order_relaxed);
  {
    std::lock_guard<std::mutex> lk(acceptMu_);
    needReaccept_ = true;
  }
  acceptCv_.notify_all();
}

void KdPipeBridge::Pump() {
  if (pipe_ == INVALID_HANDLE_VALUE ||
      !connected_.load(std::memory_order_relaxed)) {
    return;
  }

  // debugger -> guest: pull everything kd has queued, non-blocking. PeekNamedPipe
  // tells us how many bytes are available so the following ReadFile never blocks.
  for (;;) {
    DWORD avail = 0;
    if (!PeekNamedPipe(pipe_, nullptr, 0, nullptr, &avail, nullptr)) {
      SignalReaccept();
      return;
    }
    if (avail == 0) {
      break;
    }
    uint8_t buf[8192];
    const DWORD toRead =
        avail < sizeof(buf) ? avail : static_cast<DWORD>(sizeof(buf));
    DWORD got = 0;
    if (!ReadFile(pipe_, buf, toRead, &got, nullptr) || got == 0) {
      SignalReaccept();
      return;
    }
    AppendBytes(dumpFrom_, buf, got);
    {
      std::lock_guard<std::mutex> lock(rxMu_);
      rx_.insert(rx_.end(), buf, buf + got);
    }
    bytesFromDbg_.fetch_add(got, std::memory_order_relaxed);
    if (got < toRead) {
      break;
    }
  }

  // guest -> debugger: flush queued bytes. If a write fails (client gone), requeue
  // the un-written tail to the FRONT so a mid-packet disconnect never truncates
  // the kernel's stream for the reconnecting debugger.
  std::vector<uint8_t> pending;
  {
    std::lock_guard<std::mutex> lock(txMu_);
    if (!tx_.empty()) {
      pending.assign(tx_.begin(), tx_.end());
      tx_.clear();
    }
  }
  size_t off = 0;
  while (off < pending.size()) {
    DWORD wrote = 0;
    if (!WriteFile(pipe_, pending.data() + off,
                   static_cast<DWORD>(pending.size() - off), &wrote, nullptr) ||
        wrote == 0) {
      std::lock_guard<std::mutex> lock(txMu_);
      tx_.insert(tx_.begin(), pending.begin() + static_cast<std::ptrdiff_t>(off),
                 pending.end());
      SignalReaccept();
      return;
    }
    off += wrote;
    bytesToDbg_.fetch_add(wrote, std::memory_order_relaxed);
  }
}

void KdPipeBridge::AcceptProc() {
  // Re-listen loop: serve one debugger; when Pump detects it disconnected,
  // reset the pipe and wait for the next one. This lets us attach/detach kd
  // repeatedly to the same running VM.
  while (!stop_.load(std::memory_order_relaxed)) {
    const BOOL ok = ConnectNamedPipe(pipe_, nullptr);
    if (stop_.load(std::memory_order_relaxed)) {
      break;
    }
    if (!ok && GetLastError() != ERROR_PIPE_CONNECTED) {
      // Connect failed/canceled; reset and retry.
      DisconnectNamedPipe(pipe_);
      continue;
    }
    clientConnects_.fetch_add(1, std::memory_order_relaxed);
    connected_.store(true, std::memory_order_relaxed);

    // Block here (no busy-wait, no data I/O) until Pump signals a disconnect or
    // we're shutting down. All byte relay happens in Pump() on the run-loop
    // thread while connected_ is true.
    {
      std::unique_lock<std::mutex> lk(acceptMu_);
      acceptCv_.wait(lk, [this] {
        return stop_.load(std::memory_order_relaxed) || needReaccept_;
      });
      needReaccept_ = false;
    }
    if (stop_.load(std::memory_order_relaxed)) {
      break;
    }
    connected_.store(false, std::memory_order_relaxed);
    DisconnectNamedPipe(pipe_);
  }
}

} // namespace antimal::hv
