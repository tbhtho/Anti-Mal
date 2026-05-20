#include "antimal/hv/VirtualDisk.h"

#include "antimal/hv/WhpHost.h"

#include <Windows.h>
#include <objbase.h>
#include <virtdisk.h>

namespace antimal::hv {
namespace {

constexpr GUID kMicrosoftVirtualStorageVendor = {
    0xEC984AEC,
    0xA0F9,
    0x47E9,
    {0x90, 0x1F, 0x71, 0x41, 0x5A, 0x66, 0x34, 0x5B},
};

HRESULT HrFromWin32(DWORD error) {
  return HRESULT_FROM_WIN32(error);
}

VirtualDiskInfo QuerySize(HANDLE handle) {
  GET_VIRTUAL_DISK_INFO info{};
  info.Version = GET_VIRTUAL_DISK_INFO_SIZE;
  ULONG size = sizeof(info);
  ULONG used = 0;
  const DWORD error = GetVirtualDiskInformation(handle, &size, &info, &used);
  if (error != ERROR_SUCCESS) {
    throw WhpError("GetVirtualDiskInformation(size) failed", HrFromWin32(error));
  }

  VirtualDiskInfo out;
  out.virtualSize = info.Size.VirtualSize;
  out.physicalSize = info.Size.PhysicalSize;
  out.blockSize = info.Size.BlockSize;
  out.sectorSize = info.Size.SectorSize;
  return out;
}

uint32_t QueryProviderSubtype(HANDLE handle) {
  GET_VIRTUAL_DISK_INFO info{};
  info.Version = GET_VIRTUAL_DISK_INFO_PROVIDER_SUBTYPE;
  ULONG size = sizeof(info);
  ULONG used = 0;
  const DWORD error = GetVirtualDiskInformation(handle, &size, &info, &used);
  if (error != ERROR_SUCCESS) {
    return 0;
  }
  return info.ProviderSubtype;
}

uint32_t QueryVhdPhysicalSectorSize(HANDLE handle) {
  GET_VIRTUAL_DISK_INFO info{};
  info.Version = GET_VIRTUAL_DISK_INFO_VHD_PHYSICAL_SECTOR_SIZE;
  ULONG size = sizeof(info);
  ULONG used = 0;
  const DWORD error = GetVirtualDiskInformation(handle, &size, &info, &used);
  if (error != ERROR_SUCCESS) {
    return 0;
  }
  return info.VhdPhysicalSectorSize;
}

bool QueryIsLoaded(HANDLE handle) {
  GET_VIRTUAL_DISK_INFO info{};
  info.Version = GET_VIRTUAL_DISK_INFO_IS_LOADED;
  ULONG size = sizeof(info);
  ULONG used = 0;
  const DWORD error = GetVirtualDiskInformation(handle, &size, &info, &used);
  if (error != ERROR_SUCCESS) {
    return false;
  }
  return info.IsLoaded != FALSE;
}

} // namespace

VirtualDisk::VirtualDisk(std::filesystem::path path, void *handle)
    : path_(std::move(path)), handle_(handle) {}

VirtualDisk VirtualDisk::OpenReadOnly(const std::filesystem::path &path) {
  VIRTUAL_STORAGE_TYPE storage{};
  storage.DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_VHDX;
  storage.VendorId = kMicrosoftVirtualStorageVendor;

  HANDLE handle = INVALID_HANDLE_VALUE;
  const DWORD error =
      OpenVirtualDisk(&storage, path.c_str(), VIRTUAL_DISK_ACCESS_GET_INFO,
                      OPEN_VIRTUAL_DISK_FLAG_NONE, nullptr, &handle);
  if (error != ERROR_SUCCESS) {
    throw WhpError("OpenVirtualDisk failed", HrFromWin32(error));
  }
  return VirtualDisk(path, handle);
}

void VirtualDisk::CreateDifferencing(const std::filesystem::path &parentPath,
                                     const std::filesystem::path &childPath) {
  std::filesystem::create_directories(childPath.parent_path());
  std::error_code ec;
  std::filesystem::remove(childPath, ec);

  VIRTUAL_STORAGE_TYPE storage{};
  storage.DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_VHDX;
  storage.VendorId = kMicrosoftVirtualStorageVendor;

  CREATE_VIRTUAL_DISK_PARAMETERS params{};
  params.Version = CREATE_VIRTUAL_DISK_VERSION_1;
  CoCreateGuid(&params.Version1.UniqueId);
  params.Version1.MaximumSize = 0;
  params.Version1.BlockSizeInBytes = CREATE_VIRTUAL_DISK_PARAMETERS_DEFAULT_BLOCK_SIZE;
  params.Version1.SectorSizeInBytes = CREATE_VIRTUAL_DISK_PARAMETERS_DEFAULT_SECTOR_SIZE;
  const auto parentAbsolute = std::filesystem::absolute(parentPath);
  params.Version1.ParentPath = parentAbsolute.c_str();

  HANDLE handle = INVALID_HANDLE_VALUE;
  const DWORD error =
      CreateVirtualDisk(&storage, childPath.c_str(), VIRTUAL_DISK_ACCESS_CREATE,
                        nullptr, CREATE_VIRTUAL_DISK_FLAG_NONE, 0, &params,
                        nullptr, &handle);
  if (handle != INVALID_HANDLE_VALUE) {
    CloseHandle(handle);
  }
  if (error != ERROR_SUCCESS) {
    throw WhpError("CreateVirtualDisk(differencing) failed", HrFromWin32(error));
  }
}

VirtualDisk::~VirtualDisk() {
  if (handle_ && handle_ != INVALID_HANDLE_VALUE) {
    CloseHandle(static_cast<HANDLE>(handle_));
    handle_ = nullptr;
  }
}

VirtualDisk::VirtualDisk(VirtualDisk &&other) noexcept
    : path_(std::move(other.path_)), handle_(other.handle_) {
  other.handle_ = nullptr;
}

VirtualDisk &VirtualDisk::operator=(VirtualDisk &&other) noexcept {
  if (this == &other) {
    return *this;
  }
  if (handle_ && handle_ != INVALID_HANDLE_VALUE) {
    CloseHandle(static_cast<HANDLE>(handle_));
  }
  path_ = std::move(other.path_);
  handle_ = other.handle_;
  other.handle_ = nullptr;
  return *this;
}

VirtualDiskInfo VirtualDisk::QueryInfo() const {
  auto out = QuerySize(static_cast<HANDLE>(handle_));
  out.providerSubtype = QueryProviderSubtype(static_cast<HANDLE>(handle_));
  out.vhdPhysicalSectorSize =
      QueryVhdPhysicalSectorSize(static_cast<HANDLE>(handle_));
  out.isLoaded = QueryIsLoaded(static_cast<HANDLE>(handle_));
  return out;
}

} // namespace antimal::hv
