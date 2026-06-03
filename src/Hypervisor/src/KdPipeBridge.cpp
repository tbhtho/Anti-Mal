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
  // Re-listen loop: serve one debugger, and when it disconnects, reset the pipe
  // and wait for the next one. This lets us attach/detach kd repeatedly to the
  // same running VM (e.g. attach once the guest is sitting at the hang).
  std::vector<uint8_t> buffer(8192);
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
    connected_.store(true, std::memory_order_relaxed);
    clientConnects_.fetch_add(1, std::memory_order_relaxed);
    txCv_.notify_all(); // let the writer start flushing

    for (;;) {
      DWORD read = 0;
      if (!ReadFile(pipe_, buffer.data(),
                    static_cast<DWORD>(buffer.size()), &read, nullptr)) {
        break; // client disconnected / canceled
      }
      if (stop_.load(std::memory_order_relaxed)) {
        break;
      }
      if (read == 0) {
        continue;
      }
      AppendBytes(dumpFrom_, buffer.data(), read);
      {
        std::lock_guard<std::mutex> lock(rxMu_);
        rx_.insert(rx_.end(), buffer.begin(),
                   buffer.begin() + static_cast<std::ptrdiff_t>(read));
      }
      bytesFromDbg_.fetch_add(read, std::memory_order_relaxed);
    }
    // Client gone: reset the pipe + drop stale outbound bytes for the next one.
    connected_.store(false, std::memory_order_relaxed);
    DisconnectNamedPipe(pipe_);
    {
      std::lock_guard<std::mutex> lock(txMu_);
      tx_.clear();
    }
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
        break; // client disconnected mid-write; wait for the next one (re-listen)
      }
      offset += written;
      bytesToDbg_.fetch_add(written, std::memory_order_relaxed);
    }
  }
}

} // namespace antimal::hv
