#include "antimal/hv/Firmware.h"

#include <fstream>

namespace antimal::hv {

namespace {

constexpr size_t kPageSize = 0x1000;

std::vector<uint8_t> ReadFileAll(const std::filesystem::path &path) {
  std::ifstream stream(path, std::ios::binary | std::ios::ate);
  if (!stream) {
    throw WhpError("Firmware file open failed", HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND));
  }
  const std::streamsize size = stream.tellg();
  if (size <= 0) {
    throw WhpError("Firmware file is empty", HRESULT_FROM_WIN32(ERROR_INVALID_DATA));
  }
  stream.seekg(0, std::ios::beg);
  std::vector<uint8_t> bytes(static_cast<size_t>(size));
  if (!stream.read(reinterpret_cast<char *>(bytes.data()), size)) {
    throw WhpError("Firmware file read failed", HRESULT_FROM_WIN32(ERROR_READ_FAULT));
  }
  return bytes;
}

} // namespace

Firmware::Firmware(const WhpHost &host, const std::filesystem::path &path) {
  auto bytes = ReadFileAll(path);

  if (bytes.size() > kMaxFirmwareBytes) {
    throw WhpError("Firmware larger than supported maximum", E_INVALIDARG);
  }
  if ((bytes.size() % kPageSize) != 0) {
    throw WhpError("Firmware size must be a multiple of 4 KiB", E_INVALIDARG);
  }
  if (bytes.size() >= kFourGib) {
    throw WhpError("Firmware does not fit below 4 GiB", E_INVALIDARG);
  }

  const uint64_t gpa = kFourGib - bytes.size();
  // Combined OVMF.fd images include pflash/variable-store regions that OVMF
  // writes during DXE. A real pflash device should enforce block semantics
  // later; Phase 3b maps it writable so firmware can keep booting.
  region_ = std::make_unique<GuestMemoryRegion>(
      host, gpa, bytes.size(), GuestMemoryProt::ReadWriteExecute);
  region_->Write(0, bytes.data(), bytes.size());
}

uint64_t Firmware::Gpa() const noexcept {
  return region_ ? region_->Gpa() : 0;
}

size_t Firmware::Size() const noexcept {
  return region_ ? region_->Size() : 0;
}

bool Firmware::ContainsGpa(uint64_t gpa) const noexcept {
  if (!region_) {
    return false;
  }
  return gpa >= region_->Gpa() && gpa < (region_->Gpa() + region_->Size());
}

const uint8_t *Firmware::HostBytes() const noexcept {
  return region_ ? region_->HostPtr() : nullptr;
}

} // namespace antimal::hv
