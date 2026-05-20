#include "antimal/hv/GuestMemory.h"

#include <cstring>

namespace antimal::hv {

namespace {

size_t SystemPageSize() {
  SYSTEM_INFO si{};
  GetSystemInfo(&si);
  return static_cast<size_t>(si.dwPageSize);
}

} // namespace

GuestMemoryRegion::GuestMemoryRegion(const WhpHost &host, uint64_t gpa,
                                     size_t sizeBytes, GuestMemoryProt prot)
    : partition_(host.Handle()), gpa_(gpa), size_(sizeBytes) {
  const size_t pageSize = SystemPageSize();
  if (sizeBytes == 0 || (sizeBytes % pageSize) != 0) {
    throw WhpError("GuestMemoryRegion size must be a non-zero multiple of the page size",
                   E_INVALIDARG);
  }
  if ((gpa % pageSize) != 0) {
    throw WhpError("GuestMemoryRegion GPA must be page-aligned", E_INVALIDARG);
  }

  host_ = static_cast<uint8_t *>(
      VirtualAlloc(nullptr, sizeBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
  if (!host_) {
    const DWORD err = GetLastError();
    throw WhpError("VirtualAlloc for guest memory failed",
                   HRESULT_FROM_WIN32(err));
  }

  const HRESULT hr =
      WHvMapGpaRange(partition_, host_, gpa, sizeBytes,
                     static_cast<WHV_MAP_GPA_RANGE_FLAGS>(prot));
  if (FAILED(hr)) {
    VirtualFree(host_, 0, MEM_RELEASE);
    host_ = nullptr;
    throw WhpError("WHvMapGpaRange failed", hr);
  }
}

GuestMemoryRegion::~GuestMemoryRegion() {
  if (host_) {
    if (partition_) {
      WHvUnmapGpaRange(partition_, gpa_, size_);
    }
    VirtualFree(host_, 0, MEM_RELEASE);
    host_ = nullptr;
  }
}

void GuestMemoryRegion::Write(size_t offset, const void *data, size_t length) {
  if (offset > size_ || length > size_ - offset) {
    throw WhpError("GuestMemoryRegion::Write out of range", E_INVALIDARG);
  }
  std::memcpy(host_ + offset, data, length);
}

} // namespace antimal::hv
