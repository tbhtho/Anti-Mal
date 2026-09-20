#pragma once
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace antimal {
struct GuestArtifactLimits {
  uint64_t perFileBytes = 16ull * 1024 * 1024;
  uint64_t totalBytes = 64ull * 1024 * 1024;
  uint32_t files = 64;
};
struct GuestArtifactResult {
  bool written = false;
  std::filesystem::path path;
  std::string error;
};
// The existing destination and every ancestor must be local, non-reparse
// directories. Directory handles prevent replacement during the write. Guest
// names are metadata only: each output has a fresh host-generated identity.
GuestArtifactResult StoreGuestArtifact(const std::filesystem::path &directory,
    std::string_view guestName, std::string_view bytes,
    const GuestArtifactLimits &limits = {});
}
