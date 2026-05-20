#pragma once

// AntiMal in-house hypervisor — host side of the Windows Hypervisor Platform
// partition. RAII wrapper around WHV_PARTITION_HANDLE plus the few setup steps
// we need for any guest (processor count, partition setup). Devices, guest
// memory regions, and vCPUs are added by callers via the other headers in
// this directory.

#include <Windows.h>
#include <WinHvPlatform.h>

#include <cstdint>
#include <stdexcept>
#include <string>

namespace antimal::hv {

class WhpError : public std::runtime_error {
public:
  WhpError(const char *what, HRESULT hr)
      : std::runtime_error(MakeMessage(what, hr)), hr_(hr) {}

  HRESULT hr() const noexcept { return hr_; }

private:
  static std::string MakeMessage(const char *what, HRESULT hr) {
    char buf[256];
    _snprintf_s(buf, _TRUNCATE, "%s (HRESULT 0x%08lX)", what, static_cast<unsigned long>(hr));
    return std::string(buf);
  }

  HRESULT hr_;
};

// Owns a WHV partition handle. Construction creates + sets processor count +
// finalizes setup. Use Handle() to add memory regions and vCPUs.
class WhpHost {
public:
  // Throws WhpError if WHP is unavailable, not enabled, or partition creation
  // fails. Pre-condition: WinHvPlatform.dll present (it ships with Windows 10+
  // and the HypervisorPlatform optional feature must be enabled).
  explicit WhpHost(uint32_t processorCount,
                   bool enableLocalApicEmulation = false,
                   bool enablePageFaultExits = false);

  ~WhpHost();

  WhpHost(const WhpHost &) = delete;
  WhpHost &operator=(const WhpHost &) = delete;

  WHV_PARTITION_HANDLE Handle() const noexcept { return partition_; }
  uint32_t ProcessorCount() const noexcept { return processorCount_; }

  // Reports whether the host machine appears to support WHP (without actually
  // creating a partition). Cheap check used by Preflight; does not require
  // admin.
  static bool IsAvailable();

private:
  WHV_PARTITION_HANDLE partition_ = nullptr;
  uint32_t processorCount_ = 0;
};

} // namespace antimal::hv
