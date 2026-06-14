#pragma once

#include "antimal/Config.h"
#include "antimal/Types.h"

#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace antimal {

struct DetonationProgress {
  std::string runId;
  std::filesystem::path runDir;
  std::string phase;       // "staging", "booting", "running", "finishing"
  std::string message;     // Human-readable status line.
  int steps = 0;
  int totalHlts = 0;
  uint64_t ideSectorsRead = 0;
  uint64_t ideSectorsWritten = 0;
  uint64_t ideCommands = 0;
  uint32_t mmioReads = 0;
  uint32_t mmioWrites = 0;
  uint64_t ioApicDeliveries = 0;
  uint64_t elapsedMs = 0;
  // Bytes the guest wrote to COM1 since the previous progress callback.
  // Renderable in the UI as a live boot console.
  std::string newSerialBytes;
  // Plain-text snapshot of the legacy 0xB8000 VGA text framebuffer (25 rows
  // joined by "\n"). Empty when the guest hasn't written to it. Useful as a
  // "VM screen" surrogate when no real framebuffer is wired up yet.
  std::string vgaTextScreen;
  // Top three I/O ports by hit count (ordered descending). The post-disk-load
  // hot spin almost always shows up as a port hammered tens of thousands of
  // times per second.
  struct PortHit {
    uint16_t port = 0;
    uint64_t count = 0;
  };
  PortHit topPorts[3]{};
  // Current guest RIP + CS selector — matches against public Windows kernel
  // PDBs to identify the routine the guest is spinning in.
  uint64_t currentRip = 0;
  uint16_t currentCsSelector = 0;
  // Bochs VBE framebuffer snapshot. When `framebufferEnabled` is true the
  // GUI shows the captured guest pixels in its filmstrip; the host buffer
  // is mirrored by the VirtualMachine via a normal RAM mapping so the
  // snapshot is just a memcpy from the host pointer.
  bool framebufferEnabled = false;
  uint16_t framebufferWidth = 0;
  uint16_t framebufferHeight = 0;
  uint16_t framebufferBpp = 0;
};

using DetonationProgressCallback =
    std::function<void(const DetonationProgress &)>;

struct HyperVPreflight {
  std::string provider = "none";
  bool baseVhdxPresent = false;
  bool baseVhdxReadable = false;
  bool baseDiskPresent = false;
  bool rawBaseReady = false;
  bool vhdxConversionRequired = false;
  std::string baseDiskFormat = "raw";
  bool firmwarePresent = false;
  bool guestAgentPresent = false;
  bool whpDllPresent = false;
  bool whpAvailable = false;
  bool storageBootReady = false;
  bool baseBootStorageInspected = false;
  bool baseBootStorageReady = false;
  std::string baseBootStorageDetails;
  bool bootCapabilityReady = false;
  bool displayReady = false;
  bool hostChannelReady = false;
  bool networkReady = false;
  bool dynamicExecutionEnabled = false;
  bool safeToExecute = false;
  bool inHouseSelected = false;
  std::filesystem::path baseVhdxPath;
  std::filesystem::path baseDiskPath;
  std::filesystem::path firmwarePath;
  std::filesystem::path guestAgentPath;
  std::vector<std::string> messages;
  std::vector<std::string> blockers;
};

struct VhdxRawConversionResult {
  bool converted = false;
  bool skipped = false;
  uint64_t virtualSize = 0;
  uint64_t bytesRead = 0;
  uint64_t bytesWritten = 0;
  std::filesystem::path vhdxPath;
  std::filesystem::path rawPath;
  std::vector<std::string> messages;
  std::vector<std::string> errors;
};

VhdxRawConversionResult ConvertVhdxToRaw(const std::filesystem::path &vhdxPath,
                                         const std::filesystem::path &rawPath,
                                         bool force);

// True when `runDir` holds a live, exclusively-held run.lock (a detonation is
// in progress in some process). Probes by trying to open run.lock with no share
// access: ERROR_SHARING_VIOLATION means another process holds it (live), a
// successful open means a stale/unheld lock, and "not found"/other errors mean
// no reclaimable lock. The overlay-GC sweep skips dirs that are live-locked so a
// concurrent run can never delete a still-running sibling's disposable overlay.
bool RunDirIsLiveLocked(const std::filesystem::path &runDir);

// Offline registry-hive enumerator (diagnostics). Reads a raw regf hive FILE,
// navigates to startPath (backslash-separated; "" = root), and returns the key
// subtree to maxDepth as text. dumpValues decodes each key's values; filter
// (case-insensitive substring) limits printed/descended branches.
std::string DebugDumpHiveFile(const std::string &hiveFilePath,
                              const std::string &startPath,
                              const std::string &filterSubstr, bool dumpValues,
                              int maxDepth);

// A workspace run directory as seen by the retention sweep.
struct WorkspaceRunInfo {
  std::string name;          // run-dir name
  long long lastWriteTicks;  // sortable mtime (larger = newer)
  bool live = false;         // RunDirIsLiveLocked(runDir)
  bool systemDir = false;    // name starts with '_' (e.g. _base, _intel_cache)
};

// Retention policy (pure, unit-tested): returns the names of run directories to
// reclaim so that at most `keepRecent` of the most-recent non-system runs are
// kept. A live run is NEVER reclaimed (even if old) and system dirs are exempt
// and don't count toward the cap. keepRecent == 0 means unlimited (reclaim none).
std::vector<std::string> SelectRunsToReclaim(std::vector<WorkspaceRunInfo> runs,
                                             size_t keepRecent);

// Offline deploy of the execute-capable GuestAgent into a COW overlay (the
// disposable run overlay or a saved desktop snapshot), WITHOUT touching the
// base VHDX. The in-house NTFS writer is same-size-only and the /MT agent is
// larger than the agent slot already baked into the image, so this overwrites a
// large, non-critical existing file (default: the Segoe UI Emoji font) with the
// padded agent and repoints the AntiMalGuestAgent service ImagePath at it (a
// same-size hive edit). All writes land in the overlay; the base is read-only.
struct AgentOverlayDeployResult {
  bool ok = false;
  bool clobberWritten = false;
  bool serviceRepointed = false;
  uint64_t agentSize = 0;
  std::vector<std::string> notes;
};

AgentOverlayDeployResult DeployExecuteAgentIntoOverlay(
    const std::filesystem::path &baseVhdxPath,
    const std::filesystem::path &overlayPath,
    const std::filesystem::path &newAgentExe,
    const std::string &clobberNtfsPath = "Windows\\Fonts\\seguiemj.ttf",
    const std::string &clobberGuestPath = "C:\\Windows\\Fonts\\seguiemj.ttf",
    const std::string &serviceName = "AntiMalGuestAgent");

struct DetonationResult {
  bool started = false;
  bool completed = false;
  std::string status = "created";
  std::string runId;
  std::filesystem::path runDir;
  std::filesystem::path jobPath;
  std::filesystem::path journalPath;
  std::filesystem::path screenshotsDir;
  std::filesystem::path artifactsDir;
  std::filesystem::path overlayDiskPath;
  std::filesystem::path reportPath;
  DynamicRunSummary dynamicSummary;
  std::vector<std::string> commands;
  std::vector<std::string> errors;
};

class InHouseOrchestrator {
public:
  explicit InHouseOrchestrator(AppConfig config);

  HyperVPreflight Preflight() const;
  DetonationResult PrepareAndRun(
      const std::filesystem::path &samplePath, uint32_t timeoutSec,
      NetworkMode networkMode, bool executeVmCommands,
      DetonationProgressCallback progressCallback = {});

private:
  AppConfig config_;
};

class HyperVOrchestrator {
public:
  explicit HyperVOrchestrator(AppConfig config);

  HyperVPreflight Preflight() const;
  DetonationResult PrepareAndRun(
      const std::filesystem::path &samplePath, uint32_t timeoutSec,
      NetworkMode networkMode, bool executeVmCommands,
      DetonationProgressCallback progressCallback = {});

private:
  AppConfig config_;
};

} // namespace antimal
