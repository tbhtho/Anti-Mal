#include "antimal/hv/KdPipeBridge.h"

namespace antimal::hv {

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
  reader_ = std::thread([this] { ReaderProc(); });
  writer_ = std::thread([this] { WriterProc(); });
}

KdPipeBridge::~KdPipeBridge() {
  stop_.store(true, std::memory_order_relaxed);
  txCv_.notify_all();
  if (pipe_ != INVALID_HANDLE_VALUE) {
    // Unblock any in-flight ConnectNamedPipe / ReadFile / WriteFile.
    CancelIoEx(pipe_, nullptr);
  }
  if (reader_.joinable()) {
    reader_.join();
  }
  if (writer_.joinable()) {
    writer_.join();
  }
  if (pipe_ != INVALID_HANDLE_VALUE) {
    DisconnectNamedPipe(pipe_);
    CloseHandle(pipe_);
    pipe_ = INVALID_HANDLE_VALUE;
  }
}

void KdPipeBridge::SendToDebugger(const uint8_t *data, size_t size) {
  if (!data || size == 0 || pipe_ == INVALID_HANDLE_VALUE) {
    return;
  }
  {
    std::lock_guard<std::mutex> lock(txMu_);
    tx_.insert(tx_.end(), data, data + size);
    // While no client is attached, bound the backlog (drop oldest).
    if (!connected_.load(std::memory_order_relaxed) &&
        tx_.size() > kMaxTxQueue) {
      tx_.erase(tx_.begin(),
                tx_.begin() +
                    static_cast<std::ptrdiff_t>(tx_.size() - kMaxTxQueue));
    }
  }
  txCv_.notify_one();
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

void KdPipeBridge::ReaderProc() {
  // Wait for the debugger to connect. ConnectNamedPipe returns nonzero on a new
  // connection, or sets ERROR_PIPE_CONNECTED if a client connected between the
  // CreateNamedPipe and this call.
  const BOOL ok = ConnectNamedPipe(pipe_, nullptr);
  if (!ok && GetLastError() != ERROR_PIPE_CONNECTED) {
    return; // canceled (shutdown) or failed
  }
  connected_.store(true, std::memory_order_relaxed);
  txCv_.notify_all(); // let the writer start flushing the backlog

  std::vector<uint8_t> buffer(8192);
  while (!stop_.load(std::memory_order_relaxed)) {
    DWORD read = 0;
    if (!ReadFile(pipe_, buffer.data(),
                  static_cast<DWORD>(buffer.size()), &read, nullptr)) {
      break; // broken pipe / canceled
    }
    if (read == 0) {
      continue;
    }
    {
      std::lock_guard<std::mutex> lock(rxMu_);
      rx_.insert(rx_.end(), buffer.begin(),
                 buffer.begin() + static_cast<std::ptrdiff_t>(read));
    }
    bytesFromDbg_.fetch_add(read, std::memory_order_relaxed);
  }
}

void KdPipeBridge::WriterProc() {
  std::vector<uint8_t> pending;
  while (!stop_.load(std::memory_order_relaxed)) {
    {
      std::unique_lock<std::mutex> lock(txMu_);
      txCv_.wait(lock, [this] {
        return stop_.load(std::memory_order_relaxed) ||
               (connected_.load(std::memory_order_relaxed) && !tx_.empty());
      });
      if (stop_.load(std::memory_order_relaxed)) {
        return;
      }
      pending.assign(tx_.begin(), tx_.end());
      tx_.clear();
    }
    size_t offset = 0;
    while (offset < pending.size() && !stop_.load(std::memory_order_relaxed)) {
      DWORD written = 0;
      if (!WriteFile(pipe_, pending.data() + offset,
                     static_cast<DWORD>(pending.size() - offset), &written,
                     nullptr) ||
          written == 0) {
        return; // broken pipe / canceled
      }
      offset += written;
      bytesToDbg_.fetch_add(written, std::memory_order_relaxed);
    }
  }
}

} // namespace antimal::hv
