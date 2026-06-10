#include "antimal/ImageLoadTelemetry.h"

#include "antimal/FileUtil.h"  // UtcNowIso8601

#include <algorithm>
#include <cctype>
#include <cstdio>  // _snprintf_s (hex base formatting)
#include <set>

namespace antimal {

namespace {

// Lower-cases ASCII and normalizes path separators so the classifier's substring
// checks are case-insensitive and slash-agnostic (Windows accepts both), and so
// an extended-length "\\?\" (or "\\?\UNC\") prefix can't hide the real location.
// Pure, allocation-light. A short DOS-style 8.3 path ("PROGRA~1") is left as-is
// here -- it is handled by the system-prefix check below treating its expanded
// form, but we also defensively never flag a path we cannot positively place in
// a writable location, so an unexpanded short path simply doesn't match a
// writable rule (fail-closed toward "not suspicious", never a false positive).
std::string Normalize(const std::string &raw) {
  std::string out;
  out.reserve(raw.size());
  for (char c : raw) {
    if (c == '/') c = '\\';
    out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
  }
  // Strip a leading extended-length prefix so "\\?\c:\..." and
  // "\\?\unc\server\share\..." compare like ordinary paths.
  if (out.rfind("\\\\?\\unc\\", 0) == 0) {
    out = "\\\\" + out.substr(8);  // -> \\server\share\...
  } else if (out.rfind("\\\\?\\", 0) == 0) {
    out = out.substr(4);  // -> c:\...
  }
  return out;
}

bool Contains(const std::string &haystack, const char *needle) {
  return haystack.find(needle) != std::string::npos;
}

bool StartsWith(const std::string &h, const char *prefix) {
  return h.rfind(prefix, 0) == 0;
}

// Returns the directory portion (lower-cased, normalized) of a normalized path,
// i.e. everything up to and including the final backslash. "" if there is none.
std::string DirOf(const std::string &normalizedPath) {
  const auto slash = normalizedPath.find_last_of('\\');
  return slash == std::string::npos ? std::string()
                                    : normalizedPath.substr(0, slash + 1);
}

// True for a directory that is a trusted, non-writable system/program location.
// Anything matching here is NEVER flagged. We match on the path containing the
// canonical system roots (after Normalize), which is robust to the drive letter
// and to the path being a substring of a longer one (e.g. \windows\system32\...).
bool IsSystemLocation(const std::string &normalizedDirOrPath) {
  const std::string &p = normalizedDirOrPath;
  // \Windows covers System32, SysWOW64, WinSxS, and the rest of the OS tree.
  // \Program Files / \Program Files (x86) cover installed software.
  return Contains(p, "\\windows\\") || Contains(p, "\\program files");
}

// True for a directory that is a known user-writable, non-system location where
// a side-loaded / hijacked DLL is the overwhelmingly likely explanation for a
// fresh DLL load.
bool IsWritableUserLocation(const std::string &normalizedPath) {
  const std::string &p = normalizedPath;
  return Contains(p, "\\appdata\\") || Contains(p, "\\temp\\") ||
         Contains(p, "\\downloads\\") || Contains(p, "\\programdata\\") ||
         Contains(p, "\\users\\public\\") || Contains(p, "\\public\\");
}

EventRecord MakeImageEvent(const std::string &action, uint32_t pid,
                           const LoadedModule &mod,
                           const std::string &loaderImagePath) {
  EventRecord ev;
  ev.timestampUtc = UtcNowIso8601();
  ev.source = "GuestAgent";
  ev.category = "image";
  ev.action = action;
  ev.processId = pid;
  ev.imagePath = loaderImagePath;  // the loading process's image (panel header)
  ev.target = mod.path;            // the loaded module path
  ev.details["pid"] = std::to_string(pid);
  if (mod.base != 0) {
    char hex[20];
    _snprintf_s(hex, sizeof(hex), _TRUNCATE, "0x%016llX",
                static_cast<unsigned long long>(mod.base));
    ev.details["base"] = hex;
  }
  // Only a *load* of a module from a writable, non-system path is suspicious; an
  // observed-baseline module or an unload is informational.
  if (action == "image.load" &&
      IsSuspiciousModulePath(mod.path, loaderImagePath)) {
    ev.details["suspicion"] = "dll-from-writable-path";
    // Path alone can't prove in-process injection (T1055), so we tag the
    // path-based hijack techniques: search-order hijacking (.001) and explicit
    // side-loading (.002). The detail above lets the scorer/report explain why.
    ev.mitre = "T1574.001/T1574.002";
  }
  return ev;
}

}  // namespace

bool IsSuspiciousModulePath(const std::string &modulePath,
                            const std::string &loaderImagePath) {
  if (modulePath.empty()) {
    return false;
  }
  const std::string mod = Normalize(modulePath);

  // Trusted system/program locations are never suspicious -- this is what keeps
  // the normal flood of System32/WinSxS/Program Files loads silent.
  if (IsSystemLocation(mod)) {
    return false;
  }

  // (1) Module loaded from a known user-writable, non-system location.
  if (IsWritableUserLocation(mod)) {
    return true;
  }

  // (2) Application-directory side-loading: the module sits in the SAME
  // directory as the loader's own image, AND that directory is itself a
  // non-system, user-writable location (a dropped sample's own folder). A DLL
  // next to an EXE under \Windows or \Program Files is normal and was already
  // excluded above; this catches "evil.dll next to dropped sample.exe in
  // \Users\x\Downloads\".
  if (!loaderImagePath.empty()) {
    const std::string loader = Normalize(loaderImagePath);
    if (!IsSystemLocation(loader)) {
      const std::string modDir = DirOf(mod);
      const std::string loaderDir = DirOf(loader);
      if (!modDir.empty() && modDir == loaderDir &&
          (IsWritableUserLocation(loader) || IsWritableUserLocation(mod))) {
        return true;
      }
    }
  }

  // Anything else (a non-system path we cannot positively place as writable,
  // e.g. a custom install root, a network share, an unexpanded short path) is
  // left UNFLAGGED -- the collector errs toward no false positives.
  return false;
}

std::vector<EventRecord> DiffModuleSnapshots(const ProcessModuleSnapshot &prev,
                                             const ProcessModuleSnapshot &cur,
                                             bool emitBaseline,
                                             size_t baselineCap,
                                             size_t deltaCap) {
  std::vector<EventRecord> events;

  if (emitBaseline) {
    size_t count = 0;
    for (const auto &[pid, mods] : cur) {
      for (const auto &mod : mods) {
        if (count >= baselineCap) {
          if (!events.empty()) events.back().details["truncated"] = "true";
          return events;
        }
        ++count;
        events.push_back(MakeImageEvent("image.observed", pid, mod, {}));
      }
    }
    return events;
  }

  // New modules per pid -> image.load (capped). We compare module *paths* within
  // a pid; the base address rides along as a detail but is not part of identity
  // (a relocated reload of the same path is not a new module of interest).
  size_t loads = 0;
  bool truncated = false;
  for (const auto &[pid, curMods] : cur) {
    const auto prevIt = prev.find(pid);
    std::set<std::string> prevPaths;
    if (prevIt != prev.end()) {
      for (const auto &m : prevIt->second) prevPaths.insert(m.path);
    }
    // The loader image for this pid: the process's own module is conventionally
    // the first Toolhelp entry, but we don't rely on order -- pick the entry
    // whose path is the snapshot's recorded process image when present, else the
    // first module. For the diff's purposes, the loader image is only used by the
    // application-directory side-loading rule, so an empty/approximate value just
    // means that one rule doesn't fire (the absolute-location rules still do).
    std::string loaderImage = curMods.empty() ? std::string() : curMods.front().path;
    for (const auto &mod : curMods) {
      if (prevPaths.count(mod.path)) {
        continue;  // already loaded in this pid
      }
      if (loads >= deltaCap) {
        truncated = true;
        break;
      }
      ++loads;
      events.push_back(MakeImageEvent("image.load", pid, mod, loaderImage));
    }
    if (truncated) break;
  }
  if (truncated && !events.empty()) {
    events.back().details["truncated"] = "true";
  }

  // Removed modules per pid -> image.unload (uncapped). A pid gone entirely from
  // `cur` reports all of its previously-loaded modules as unloaded.
  for (const auto &[pid, prevMods] : prev) {
    const auto curIt = cur.find(pid);
    std::set<std::string> curPaths;
    if (curIt != cur.end()) {
      for (const auto &m : curIt->second) curPaths.insert(m.path);
    }
    for (const auto &mod : prevMods) {
      if (!curPaths.count(mod.path)) {
        events.push_back(MakeImageEvent("image.unload", pid, mod, {}));
      }
    }
  }

  return events;
}

}  // namespace antimal
