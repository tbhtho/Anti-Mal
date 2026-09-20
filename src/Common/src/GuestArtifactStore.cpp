#include "antimal/GuestArtifactStore.h"
#include "antimal/FileUtil.h"
#include <windows.h>
#include <algorithm>
#include <vector>

namespace antimal {
namespace {
struct Handles {
  std::vector<HANDLE> values;
  ~Handles() { for (auto h : values) CloseHandle(h); }
};
bool ValidName(std::string_view name) {
  if (name.empty() || name.size() > 128 || name == "." || name == ".." ||
      name.back() == '.') return false;
  for (unsigned char c : name) {
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
      return false;
  }
  std::string base(name.substr(0, name.find('.')));
  for (char &c : base) if (c >= 'a' && c <= 'z') c -= 'a' - 'A';
  if (base == "CON" || base == "PRN" || base == "AUX" || base == "NUL")
    return false;
  return !(base.size() == 4 && (base.substr(0, 3) == "COM" ||
          base.substr(0, 3) == "LPT") && base[3] >= '1' && base[3] <= '9');
}
}

GuestArtifactResult StoreGuestArtifact(const std::filesystem::path &directory,
    std::string_view guestName, std::string_view bytes,
    const GuestArtifactLimits &limits) {
  GuestArtifactResult result;
  auto fail = [&](const std::string &reason) {
    result.error = reason;
    return result;
  };
  if (!ValidName(guestName)) return fail("invalid guest artifact name");
  if (bytes.size() > limits.perFileBytes || bytes.size() > limits.totalBytes)
    return fail("artifact byte quota exceeded");
  std::error_code ec;
  const auto root = std::filesystem::absolute(directory, ec).lexically_normal();
  if (ec || root.root_name().wstring().size() != 2 ||
      root.root_name().wstring()[1] != L':')
    return fail("artifact destination must be a local drive path");
  Handles held;
  auto current = root.root_path();
  auto pin = [&](const std::filesystem::path &path) {
    HANDLE h = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    held.values.push_back(h);
    FILE_ATTRIBUTE_TAG_INFO info{};
    return GetFileInformationByHandleEx(h, FileAttributeTagInfo, &info, sizeof(info)) &&
        (info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
        !(info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
  };
  if (!pin(current)) return fail("artifact root is unavailable or redirected");
  for (const auto &part : root.relative_path()) {
    current /= part;
    if (!pin(current)) return fail("artifact directory is unavailable or redirected");
  }
  // One writer per run directory. Prevent concurrent workers from independently
  // observing spare quota and consuming it twice. Never truncate this lock file.
  const auto lockPath = root / L".artifact-write.lock";
  HANDLE lock = CreateFileW(lockPath.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
      nullptr, OPEN_ALWAYS, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (lock == INVALID_HANDLE_VALUE) return fail("artifact writer unavailable");
  held.values.push_back(lock);
  FILE_ATTRIBUTE_TAG_INFO lockInfo{};
  if (!GetFileInformationByHandleEx(lock, FileAttributeTagInfo, &lockInfo,
                                    sizeof(lockInfo)) ||
      (lockInfo.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)))
    return fail("artifact lock is redirected");
  uint64_t total = 0;
  uint32_t count = 0;
  std::filesystem::directory_iterator it(root, ec), end;
  if (ec) return fail("cannot enumerate artifact quota");
  for (; it != end; it.increment(ec)) {
    if (ec) return fail("cannot enumerate artifact quota");
    if (it->path().filename() == L".artifact-write.lock") continue;
    const DWORD attrs = GetFileAttributesW(it->path().c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs &
        (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)))
      return fail("artifact destination contains redirected or nested content");
    const auto size = it->file_size(ec);
    if (ec || size > limits.totalBytes - total)
      return fail("existing artifact quota exceeded");
    total += size;
    if (++count >= limits.files) return fail("artifact file quota exceeded");
  }
  if (ec) return fail("cannot enumerate artifact quota");
  if (count >= limits.files || bytes.size() > limits.totalBytes - total)
    return fail("artifact aggregate quota exceeded");
  result.path = root / ("guest-" + MakeRunId() + ".bin");
  HANDLE file = CreateFileW(result.path.c_str(), GENERIC_WRITE, 0, nullptr,
      CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (file == INVALID_HANDLE_VALUE) return fail("cannot create fresh artifact");
  held.values.push_back(file);
  size_t offset = 0;
  while (offset < bytes.size()) {
    const DWORD chunk = static_cast<DWORD>(std::min<size_t>(bytes.size() - offset, 1024 * 1024));
    DWORD written = 0;
    if (!WriteFile(file, bytes.data() + offset, chunk, &written, nullptr) || written != chunk)
      return fail("artifact write incomplete; partial evidence retained");
    offset += written;
  }
  if (!FlushFileBuffers(file)) return fail("artifact flush failed; partial evidence retained");
  result.written = true;
  return result;
}
}
