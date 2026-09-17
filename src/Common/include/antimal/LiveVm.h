#pragma once

// LiveVm - host-side access to a running "Boot VM (live)" / detonation session.
//
// This is the attachment layer the agent tools build on. A live session is
// already visible to any host process: the VMM mirrors the guest framebuffer
// into the named section `Local\AntiMalLiveFrameV1` (antimal/hv/LiveFrameShm.h)
// and tails `<workspace>\_live-input.bin` for framed input records
// (antimal/hv/LiveInputProtocol.h). Nothing here starts or owns the VM -- it
// observes and drives the session the GUI (or `detonate`) is running, which is
// exactly what makes agent action visible in the same window the analyst
// watches.
//
// Windows-side counterpart to the pure math in VmPointer.h: this is where the
// capture -> locate -> nudge -> capture loop actually talks to the VM.

#include "antimal/Config.h"
#include "antimal/VmPointer.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace antimal {

// Wire contract constants shared by the VMM publisher, the GUI reader and
// every agent tool (keep in lockstep with antimal/hv/LiveFrameShm.h).
constexpr wchar_t kLiveFrameShmName[] = L"Local\\AntiMalLiveFrameV1";
constexpr uint32_t kLiveFrameMagic = 0x414D4C46u; // 'AMLF'
constexpr size_t kLiveFrameHeaderBytes = 64;
constexpr wchar_t kLiveInputFileName[] = L"_live-input.bin";

struct LiveFrame {
  bool present = false;
  uint32_t width = 0;
  uint32_t height = 0;
  uint64_t frameSeq = 0;
  BgrxFrame frame; // BGRX pixels, tightly packed
  std::string error;
};

// Latest complete (untorn) frame from the live section. `present=false` with
// `error` set when no session is publishing.
LiveFrame ReadLiveFrame(const std::wstring &shmName = kLiveFrameShmName);

// Waits for a frame newer than `prevSeq` (i.e. the guest painted after our
// input). Returns the newest frame on timeout with `present=true` still true
// when a frame exists -- callers measure and decide; they are not left blind.
LiveFrame WaitForLiveFrame(uint64_t prevSeq,
                           const std::wstring &shmName = kLiveFrameShmName,
                           int timeoutMs = 700);

// Captures the current live frame to a PNG (reuses the Common framebuffer
// encoder). Returns false with `error` set when no session is publishing or
// the write failed.
bool CaptureLiveFrameToPng(const std::wstring &shmName,
                           const std::filesystem::path &outPng,
                           LiveFrame *info = nullptr,
                           std::string *error = nullptr);

struct LiveRun {
  std::filesystem::path dir;
  std::filesystem::path reportJson;  // may not exist yet (run in flight)
  std::filesystem::path eventsJsonl; // may not exist yet
  bool HasJournal() const;
};

// Newest run directory under workspaceRoot ranked by most recent activity.
// Mirrors the GUI's discovery (App/src/WebViewHost.cpp) so agent tools and the
// live console always agree on "the current run".
LiveRun FindNewestRun(const std::filesystem::path &workspaceRoot);

struct ProcessEntry {
  uint32_t pid = 0;
  std::wstring image;
  // Best-effort command line (PEB read). Empty when unreadable/protected.
  // Used to distinguish the `detonate` VM host from an unrelated `scan`.
  std::wstring commandLine;
};

std::vector<ProcessEntry> FindProcessesByName(const std::wstring &exeName);

struct LiveVmStatus {
  bool framePresent = false;
  uint32_t width = 0;
  uint32_t height = 0;
  uint64_t frameSeq = 0;
  bool frameAdvancing = false;
  double fps = 0.0;
  bool blank = false; // near-uniform frame (pre-desktop / mid-repaint)
  uint64_t inputFileBytes = 0;
  LiveRun run;
  std::vector<ProcessEntry> hostCliProcesses; // the detonate/live host process
};

// Samples the live session (two frame reads `observeMs` apart) plus the newest
// run, the input file and the host processes.
LiveVmStatus QueryLiveVmStatus(const AppConfig &config, int observeMs = 400);

// ---- Input ------------------------------------------------------------------

// Appends framed input records to a live-input file. One instance per session;
// the path is `<workspaceRoot>\_live-input.bin` unless told otherwise.
class LiveInputWriter {
public:
  explicit LiveInputWriter(std::filesystem::path file) : file_(std::move(file)) {}

  bool AppendFramed(const std::vector<uint8_t> &bytes) const;
  bool KeyScancodes(const std::vector<uint8_t> &scancodes) const;
  bool Text(const std::string &text, int perCharMs = 25) const;
  bool NamedKey(const std::string &name) const;
  bool Chord(const std::string &spec) const;
  // `screenDx/screenDy` are screen-space (x right, y down); the PS/2 packet
  // encodes Y up, so this flips dy internally.
  bool Mouse(uint8_t buttons, int screenDx, int screenDy) const;

  const std::filesystem::path &Path() const { return file_; }

private:
  std::filesystem::path file_;
};

// Key-name helpers shared by the CLI and the MCP tools (single source of truth
// for the key table).
bool NamedKeyScancodes(const std::string &name, std::vector<uint8_t> *out);
bool ChordScancodes(const std::string &spec, std::vector<uint8_t> *out);

// ---- Coordinate-based interaction ------------------------------------------

struct AimOutcome {
  bool ok = false;
  int cursorX = 0; // pointer hotspot after the last move (screen space)
  int cursorY = 0;
  int errorX = 0; // remaining error when the loop stopped
  int errorY = 0;
  int iterations = 0;
  bool learned = false; // sprite learning succeeded
  std::string error;
};

// Moves the guest pointer to (targetX, targetY) with the closed loop:
// probe -> learn the sprite -> step -> measure -> correct. `holdButtons` is
// preserved on every injected move (dragging). Callers click afterwards.
AimOutcome AimLivePointer(const LiveInputWriter &input,
                          const std::wstring &shmName, int targetX, int targetY,
                          uint8_t holdButtons = 0, int tolerance = 4,
                          int maxIterations = 16);

struct ClickOutcome {
  bool ok = false;
  AimOutcome aim;
  std::string error;
};

// button: 0 = left, 1 = right, 2 = middle. clicks: 1 or 2.
ClickOutcome ClickLivePointer(const LiveInputWriter &input,
                              const std::wstring &shmName, int x, int y,
                              int button = 0, int clicks = 1, int tolerance = 4,
                              int maxIterations = 16);

// Press at (x1, y1), drag to (x2, y2), release.
ClickOutcome DragLivePointer(const LiveInputWriter &input,
                             const std::wstring &shmName, int x1, int y1,
                             int x2, int y2, int button = 0, int tolerance = 4,
                             int maxIterations = 16);

} // namespace antimal
