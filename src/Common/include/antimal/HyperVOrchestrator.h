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
