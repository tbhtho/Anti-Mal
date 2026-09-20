#include "antimal/LiveVm.h"

#include "antimal/FileUtil.h"
#include "antimal/Screenshot.h"
#include "antimal/hv/LiveFrameShm.h"
#include "antimal/hv/LiveInputProtocol.h"

#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <cstring>
#include <thread>

namespace antimal {
namespace {

// Mirror of the publisher's header (antimal/hv/LiveFrameShm.h). Kept local
// because the wire layout must stay a plain byte contract across processes.
struct LiveFrameHeader {
  uint32_t magic;
  uint32_t version;
  uint32_t width;
  uint32_t height;
  uint32_t bpp;
  uint32_t format; // 0 = BGRX
  uint32_t byteLength;
  uint32_t reserved;
  volatile uint64_t frameSeq;
};

uint64_t PathMtime(const std::filesystem::path &p) {
  WIN32_FILE_ATTRIBUTE_DATA fad{};
  if (!GetFileAttributesExW(p.c_str(), GetFileExInfoStandard, &fad)) {
    return 0;
  }
  ULARGE_INTEGER t{};
  t.LowPart = fad.ftLastWriteTime.dwLowDateTime;
  t.HighPart = fad.ftLastWriteTime.dwHighDateTime;
  return t.QuadPart;
}

// Best-effort command line for a running process (PEB walk). Only used to
// distinguish the VM host (`detonate`) from an unrelated HostCli invocation
// before terminating anything. Returns empty when unreadable -- callers must
// treat empty as "do not touch" unless the caller explicitly forced it.
std::wstring ReadProcessCommandLine(uint32_t pid) {
  std::wstring out;
  HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                         FALSE, pid);
  if (!h) {
    return out;
  }
  using NtQueryInformationProcessFn = LONG(WINAPI *)(HANDLE, ULONG, PVOID,
                                                     ULONG, PULONG);
  static const auto ntQuery = reinterpret_cast<NtQueryInformationProcessFn>(
      GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                     "NtQueryInformationProcess"));
  if (ntQuery) {
    PROCESS_BASIC_INFORMATION pbi{};
    if (ntQuery(h, 0 /*ProcessBasicInformation*/, &pbi, sizeof(pbi), nullptr) ==
            0 &&
        pbi.PebBaseAddress) {
      // PEB->ProcessParameters (x64 offset 0x20) and
      // RTL_USER_PROCESS_PARAMETERS->CommandLine (x64 offset 0x70) are stable
      // ABI layout on x64 Windows; read them defensively.
      PVOID params = nullptr;
      SIZE_T got = 0;
      const auto *peb = reinterpret_cast<const uint8_t *>(pbi.PebBaseAddress);
      if (ReadProcessMemory(h, peb + 0x20, &params, sizeof(params), &got) &&
          params) {
        UNICODE_STRING us{};
        const auto *rpp = reinterpret_cast<const uint8_t *>(params);
        if (ReadProcessMemory(h, rpp + 0x70, &us, sizeof(us), &got) &&
            us.Buffer && us.Length > 0 &&
            us.Length <= 32 * 1024) {
          std::wstring buf(us.Length / sizeof(wchar_t), L'\0');
          if (ReadProcessMemory(h, us.Buffer, buf.data(), us.Length, &got)) {
            out = buf;
          }
        }
      }
    }
  }
  CloseHandle(h);
  return out;
}

// Track the established sprite across a move. Learning is reserved for bounded
// probes, so unrelated changing content cannot silently replace the pointer.
struct MoveMeasure {
  bool valid = false;
  int x = 0, y = 0; // pointer top-left after the move
  int dx = 0, dy = 0; // measured screen-space delta
};

MoveMeasure MeasureMove(const BgrxFrame &cur, int prevX,
                        int prevY, int injX, int injY,
                        const CursorSprite &sprite) {
  MoveMeasure m;
  const int radius = std::max(48, std::max(std::abs(injX), std::abs(injY)) * 4 + 32);
  const CursorMatch hit =
      TrackCursor(cur, sprite, prevX + injX, prevY + injY, radius);
  if (hit.valid) {
    m.valid = true;
    m.x = hit.x;
    m.y = hit.y;
    m.dx = hit.x - prevX;
    m.dy = hit.y - prevY;
  }
  return m;
}

} // namespace

LiveFrame ReadLiveFrame(const std::wstring &shmName) {
  LiveFrame out;
  HANDLE map = OpenFileMappingW(FILE_MAP_READ, FALSE, shmName.c_str());
  if (!map) {
    out.error = "live frame section not present (no live VM running?)";
    return out;
  }
  const auto *view = static_cast<const uint8_t *>(
      MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0));
  if (!view) {
    CloseHandle(map);
    out.error = "cannot map live frame section";
    return out;
  }
  const auto *hdr = reinterpret_cast<const LiveFrameHeader *>(view);
  if (hdr->magic != kLiveFrameMagic) {
    out.error = "live frame section has the wrong magic";
  } else {
    // Seqlock: latch the sequence, copy, verify it did not change under us.
    for (int attempt = 0; attempt < 4; ++attempt) {
      const uint64_t seq = hdr->frameSeq;
      const uint32_t w = hdr->width;
      const uint32_t h = hdr->height;
      const uint32_t bpp = hdr->bpp;
      if (seq == 0 || w == 0 || h == 0 || bpp != 32 || w > 8192 || h > 8192 ||
          static_cast<uint64_t>(w) * h * 4ull > 16ull * 1024 * 1024) {
        out.error = "no complete frame published yet";
        break;
      }
      out.frame.width = w;
      out.frame.height = h;
      out.frame.pixels.resize(static_cast<size_t>(w) * h * 4);
      std::memcpy(out.frame.pixels.data(), view + kLiveFrameHeaderBytes,
                  out.frame.pixels.size());
      MemoryBarrier();
      if (hdr->frameSeq == seq) {
        out.present = true;
        out.frameSeq = seq;
        out.width = w;
        out.height = h;
        break;
      }
      out.error = "torn frame";
    }
  }
  UnmapViewOfFile(view);
  CloseHandle(map);
  return out;
}

LiveFrame WaitForLiveFrame(uint64_t prevSeq, const std::wstring &shmName,
                           int timeoutMs) {
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
  for (;;) {
    LiveFrame frame = ReadLiveFrame(shmName);
    if (frame.present && frame.frameSeq != prevSeq) {
      return frame;
    }
    if (std::chrono::steady_clock::now() >= deadline) {
      LiveFrame missing;
      missing.error = "no newer VM frame within wait budget";
      return missing;
    }
    Sleep(20);
  }
}

bool CaptureLiveFrameToPng(const std::wstring &shmName,
                           const std::filesystem::path &outPng,
                           LiveFrame *info, std::string *error) {
  LiveFrame f = ReadLiveFrame(shmName);
  if (!f.present) {
    if (error) {
      *error = f.error;
    }
    return false;
  }
  if (!outPng.parent_path().empty()) {
    EnsureDirectory(outPng.parent_path());
  }
  if (!EncodeFramebufferPng(outPng, f.frame.pixels.data(),
                            static_cast<int>(f.width),
                            static_cast<int>(f.height), 4)) {
    if (error) {
      *error = "PNG encode/write failed";
    }
    return false;
  }
  if (info) {
    *info = std::move(f);
  }
  return true;
}

bool LiveRun::HasJournal() const {
  std::error_code ec;
  return std::filesystem::exists(eventsJsonl, ec);
}

bool FinalizeRequested(const std::filesystem::path &runDir) {
  if (runDir.empty()) {
    return false;
  }
  std::error_code ec;
  return std::filesystem::exists(runDir / L"finalize.request", ec);
}

LiveRun FindNewestRun(const std::filesystem::path &workspaceRoot) {
  namespace fs = std::filesystem;
  LiveRun best;
  uint64_t bestMtime = 0;
  std::error_code ec;
  if (!fs::is_directory(workspaceRoot, ec)) {
    return best;
  }
  for (const auto &e : fs::directory_iterator(workspaceRoot, ec)) {
    if (!e.is_directory(ec)) {
      continue;
    }
    const fs::path dir = e.path();
    const std::wstring name = dir.filename().wstring();
    if (name.empty() || name[0] == L'_') {
      continue; // _base, _intel_cache, _mcp, _live-input.bin's dir...
    }
    // Rank by recent activity, not report.json existence: an in-flight live
    // boot has events.jsonl + screenshots but no report.json yet.
    uint64_t m = PathMtime(dir);
    m = std::max(m, PathMtime(dir / L"report.json"));
    m = std::max(m, PathMtime(dir / L"events.jsonl"));
    m = std::max(m, PathMtime(dir / L"screenshots"));
    if (m == 0) {
      continue;
    }
    if (m > bestMtime) {
      bestMtime = m;
      best.dir = dir;
      best.reportJson = dir / L"report.json";
      best.eventsJsonl = dir / L"events.jsonl";
    }
  }
  return best;
}

std::vector<ProcessEntry> FindProcessesByName(const std::wstring &exeName) {
  std::vector<ProcessEntry> out;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) {
    return out;
  }
  PROCESSENTRY32W pe{};
  pe.dwSize = sizeof(pe);
  if (Process32FirstW(snap, &pe)) {
    do {
      if (_wcsicmp(pe.szExeFile, exeName.c_str()) == 0) {
        ProcessEntry entry;
        entry.pid = pe.th32ProcessID;
        entry.image = pe.szExeFile;
        entry.commandLine = ReadProcessCommandLine(pe.th32ProcessID);
        out.push_back(std::move(entry));
      }
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  return out;
}

LiveVmStatus QueryLiveVmStatus(const AppConfig &config, int observeMs) {
  LiveVmStatus s;
  const LiveFrame a = ReadLiveFrame();
  s.framePresent = a.present;
  s.width = a.width;
  s.height = a.height;
  s.frameSeq = a.frameSeq;
  if (a.present) {
    s.blank = hv::LiveFrameIsBlank(a.frame.pixels.data(), a.width, a.height,
                                   a.width * 4);
  }
  if (observeMs > 0) {
    Sleep(observeMs);
    const LiveFrame b = ReadLiveFrame();
    if (b.present) {
      s.framePresent = true;
      s.width = b.width;
      s.height = b.height;
      s.frameAdvancing = b.frameSeq > a.frameSeq;
      s.fps = static_cast<double>(b.frameSeq - a.frameSeq) * 1000.0 /
              static_cast<double>(observeMs);
      s.frameSeq = b.frameSeq;
      s.blank = hv::LiveFrameIsBlank(b.frame.pixels.data(), b.width, b.height,
                                     b.width * 4);
    }
  }
  const std::filesystem::path input =
      config.workspaceRoot / kLiveInputFileName;
  std::error_code ec;
  if (std::filesystem::exists(input, ec)) {
    s.inputFileBytes = std::filesystem::file_size(input, ec);
  }
  s.run = FindNewestRun(config.workspaceRoot);
  s.hostCliProcesses = FindProcessesByName(L"AntiMal.HostCli.exe");
  return s;
}

bool LiveInputWriter::AppendFramed(const std::vector<uint8_t> &bytes) const {
  if (bytes.empty()) {
    return true; // nothing to inject is not a failure
  }
  HANDLE h = CreateFileW(file_.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ,
                         nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) {
    return false;
  }
  DWORD written = 0;
  const BOOL ok =
      WriteFile(h, bytes.data(), static_cast<DWORD>(bytes.size()), &written,
                nullptr);
  FlushFileBuffers(h);
  CloseHandle(h);
  return ok && written == bytes.size();
}

bool LiveInputWriter::KeyScancodes(const std::vector<uint8_t> &sc) const {
  return AppendFramed(hv::EncodeKeyRecords(sc));
}

bool LiveInputWriter::Text(const std::string &text, int perCharMs) const {
  bool ok = true;
  for (char ch : text) {
    const std::vector<uint8_t> tap = hv::AsciiToSet1Tap(ch);
    if (tap.empty()) {
      continue; // unmappable character: skip, matching the CLI behavior
    }
    ok = AppendFramed(hv::EncodeKeyRecords(tap)) && ok;
    if (perCharMs > 0) {
      Sleep(static_cast<DWORD>(perCharMs));
    }
  }
  return ok;
}

bool LiveInputWriter::NamedKey(const std::string &name) const {
  std::vector<uint8_t> tap;
  if (!NamedKeyScancodes(name, &tap)) {
    return false;
  }
  return AppendFramed(hv::EncodeKeyRecords(tap));
}

bool LiveInputWriter::Chord(const std::string &spec) const {
  std::vector<uint8_t> tap;
  if (!ChordScancodes(spec, &tap)) {
    return false;
  }
  return AppendFramed(hv::EncodeKeyRecords(tap));
}

bool LiveInputWriter::Mouse(uint8_t buttons, int screenDx,
                            int screenDy) const {
  // Screen space has Y down; the wire encoder flips it to PS/2 Y-up once and
  // splits displacements beyond the signed-8-bit packet limit (a 300 px step
  // used to wrap). No clamping here -- the splitter preserves the total.
  return AppendFramed(hv::EncodeMouseScreenMoveRecords(buttons, screenDx, screenDy));
}

bool NamedKeyScancodes(const std::string &name, std::vector<uint8_t> *out) {
  struct KeyDef {
    const char *name;
    uint8_t code;
    bool extended;
  };
  static const KeyDef kKeys[] = {
      {"enter", 0x1C, false}, {"return", 0x1C, false}, {"tab", 0x0F, false},
      {"esc", 0x01, false},   {"escape", 0x01, false}, {"space", 0x39, false},
      {"backspace", 0x0E, false}, {"delete", 0x53, true}, {"del", 0x53, true},
      {"up", 0x48, true},     {"down", 0x50, true},    {"left", 0x4B, true},
      {"right", 0x4D, true},  {"home", 0x47, true},    {"end", 0x4F, true},
      {"f1", 0x3B, false},    {"f2", 0x3C, false},     {"f3", 0x3D, false},
      {"f4", 0x3E, false},    {"f5", 0x3F, false},     {"f6", 0x40, false},
      {"f7", 0x41, false},    {"f8", 0x42, false},     {"f9", 0x43, false},
      {"f10", 0x44, false},   {"f11", 0x57, false},    {"f12", 0x58, false},
  };
  const std::string lower = ToLowerAscii(name);
  for (const KeyDef &k : kKeys) {
    if (lower == k.name) {
      if (k.extended) {
        out->push_back(0xE0);
      }
      out->push_back(k.code);
      if (k.extended) {
        out->push_back(0xE0);
      }
      out->push_back(static_cast<uint8_t>(k.code | 0x80));
      return true;
    }
  }
  return false;
}

// Chord like "ctrl+shift+esc", "alt+f4", "win+r": hold the modifiers, tap the
// final key, release the modifiers (modifier make/release around the tap).
bool ChordScancodes(const std::string &spec, std::vector<uint8_t> *out) {
  std::vector<std::string> parts;
  std::string cur;
  for (char c : spec) {
    if (c == '+') {
      parts.push_back(cur);
      cur.clear();
    } else {
      cur.push_back(c);
    }
  }
  parts.push_back(cur);
  if (parts.size() < 2) {
    return false;
  }
  std::vector<uint8_t> makes;
  // Modifier RELEASE GROUPS: releases are emitted in reverse modifier order, but
  // the bytes INSIDE an extended release (E0 DB for the Windows key) must stay in
  // order. Flattening them and reversing every byte produced DB E0, a malformed
  // release that can strand the modifier in the guest.
  std::vector<std::vector<uint8_t>> releases;
  for (size_t i = 0; i + 1 < parts.size(); ++i) {
    const std::string m = ToLowerAscii(parts[i]);
    if (m == "ctrl" || m == "control") {
      makes.push_back(0x1D);
      releases.push_back({0x9D});
    } else if (m == "alt") {
      makes.push_back(0x38);
      releases.push_back({0xB8});
    } else if (m == "shift") {
      makes.push_back(0x2A);
      releases.push_back({0xAA});
    } else if (m == "win" || m == "meta") {
      makes.push_back(0xE0);
      makes.push_back(0x5B);
      releases.push_back({0xE0, 0xDB});
    } else {
      return false;
    }
  }
  std::vector<uint8_t> tap;
  const std::string &last = parts.back();
  if (!NamedKeyScancodes(last, &tap) && last.size() == 1) {
    tap = hv::AsciiToSet1Tap(last[0]);
  }
  if (tap.empty()) {
    return false;
  }
  out->insert(out->end(), makes.begin(), makes.end());
  out->insert(out->end(), tap.begin(), tap.end());
  for (auto it = releases.rbegin(); it != releases.rend(); ++it) {
    out->insert(out->end(), it->begin(), it->end());
  }
  return true;
}

AimOutcome AimLivePointer(const LiveInputWriter &input,
                          const std::wstring &shmName, int targetX, int targetY,
                          uint8_t holdButtons, int tolerance,
                          int maxIterations) {
  AimOutcome out;
  LiveFrame cur = ReadLiveFrame(shmName);
  if (!cur.present) {
    out.error = "no live VM framebuffer: " + cur.error;
    return out;
  }
  if (!cur.frame.Contains(targetX, targetY)) {
    out.error = "target is outside the guest screen";
    return out;
  }

  // Optional bounded diagnostic capture for investigating guest pointer feedback.
  wchar_t diagnosticDir[32768]{};
  const DWORD diagnosticLength = GetEnvironmentVariableW(
      L"ANTIMAL_POINTER_DIAGNOSTICS", diagnosticDir, 32768);
  int diagnosticSequence = 0;
  auto captureDiagnostic = [&](const LiveFrame &frame) {
    if (!diagnosticLength || diagnosticLength >= 32768 || !frame.present ||
        diagnosticSequence >= 40) return;
    const auto path = std::filesystem::path(diagnosticDir) /
        (std::to_wstring(++diagnosticSequence) + L".png");
    EncodeFramebufferPng(path, frame.frame.pixels.data(), frame.frame.width,
                         frame.frame.height, 4);
  };
  // 1. Prime the pointer. Windows does not render a mouse pointer until the
  // first mouse event, and the framebuffer shows nothing for the learner until
  // it does -- live testing (2026-09-17) had the whole aim fail on a freshly
  // booted guest for exactly this reason. Send a tiny wake move and settle on a
  // frame pair that already contains the drawn pointer.
  input.Mouse(holdButtons, 1, 0);
  Sleep(800);
  {
    LiveFrame primed = WaitForLiveFrame(cur.frameSeq, shmName, 900);
    if (primed.present) {
      cur = std::move(primed);
      LiveFrame settled = WaitForLiveFrame(cur.frameSeq, shmName, 700);
      if (settled.present) {
        cur = std::move(settled);
      }
    }
  }

  captureDiagnostic(cur);

  // 2. Probe until the pointer demonstrably moves, then learn its sprite. The
  // probe also measures the pointer's response, so a dead input channel fails
  // fast instead of silently clicking nothing.
  CursorSprite sprite;
  int px = 0, py = 0;
  bool havePos = false;
  static const int kProbes[4][2] = {{12, 0}, {-12, 0}, {0, 12}, {0, -12}};
  auto probeSprite = [&](int dx, int dy) {
    ShiftLearnResult learned;
    if (!input.Mouse(holdButtons, dx, dy)) return learned;
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(5000);
    uint64_t sequence = cur.frameSeq;
    LiveFrame last;
    do {
      auto next = WaitForLiveFrame(sequence, shmName, 300);
      if (!next.present) continue;
      sequence = next.frameSeq;
      if (next.frame.pixels != cur.frame.pixels) {
        learned = LearnCursorByKnownShift(cur.frame, next.frame, dx, dy);
      }
      last = std::move(next);
      if (learned.valid) break;
    } while (std::chrono::steady_clock::now() < deadline);
    if (last.present) {
      captureDiagnostic(last);
      cur = std::move(last);
    }
    return learned;
  };
  for (const auto &probe : kProbes) {
    const auto learn = probeSprite(probe[0], probe[1]);
    if (learn.valid) {
      sprite = learn.sprite;
      px = learn.x;
      py = learn.y;
      havePos = true;
      out.learned = true;
      break;
    }
  }
  if (!havePos) {
    out.error =
        "could not locate the guest pointer; is the VM at an interactive "
        "desktop?";
    return out;
  }

  // 2. Closed loop: plan, inject, measure, correct.
  PointerAimState st;
  st.targetX = targetX;
  st.targetY = targetY;
  st.cursorX = px;
  st.cursorY = py;
  st.tolerance = tolerance;
  st.maxIterations = maxIterations;
  int shapeChanges = 0;
  for (;;) {
    const PointerAimState::Decision d = st.Next();
    if (d.done) {
      out.ok = !d.failed;
      if (d.failed) {
        out.error = st.stalls >= 4 ? "pointer did not respond to injected input"
                                   : "aim budget exhausted before reaching the "
                                     "target";
      }
      break;
    }
    input.Mouse(holdButtons, d.dx, d.dy);
    MoveMeasure m;
    LiveFrame next;
    const auto moveDeadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(5000);
    uint64_t sequence = cur.frameSeq;
    do {
      auto fresh = WaitForLiveFrame(sequence, shmName, 300);
      if (!fresh.present) continue;
      sequence = fresh.frameSeq;
      next = std::move(fresh);
      m = MeasureMove(next.frame, px, py, d.dx, d.dy, sprite);
      if (m.valid && (m.dx != 0 || m.dy != 0)) break;
    } while (std::chrono::steady_clock::now() < moveDeadline);
    if (!next.present) {
      out.error = "live frames stopped mid-aim";
      break;
    }
    captureDiagnostic(next);
    cur = std::move(next);
    if (m.valid) {
      px = m.x;
      py = m.y;
      st.Observe(d.dx, d.dy, m.dx, m.dy);
    } else {
      // Entering an edit control changes the arrow to an I-beam. Establish a
      // NEW observed sprite with a bounded probe; never click at a prediction.
      bool reacquired = false;
      if (++shapeChanges <= 2) {
        for (const auto &probe : kProbes) {
          auto learned = probeSprite(probe[0], probe[1]);
          if (!learned.valid) continue;
          sprite = std::move(learned.sprite);
          px = learned.x;
          py = learned.y;
          st.cursorX = px;
          st.cursorY = py;
          ++st.iterations;
          st.stalls = 0;
          reacquired = true;
          break;
        }
      }
      if (!reacquired) {
        out.error = "lost the guest pointer while aiming";
        break;
      }
    }
  }
  out.cursorX = st.cursorX;
  out.cursorY = st.cursorY;
  out.errorX = targetX - st.cursorX;
  out.errorY = targetY - st.cursorY;
  out.iterations = st.iterations;
  return out;
}

ClickOutcome ClickLivePointer(const LiveInputWriter &input,
                              const std::wstring &shmName, int x, int y,
                              int button, int clicks, int tolerance,
                              int maxIterations) {
  ClickOutcome out;
  const uint8_t bit =
      button == 1 ? 0x02u : (button == 2 ? 0x04u : 0x01u);
  out.aim = AimLivePointer(input, shmName, x, y, 0, tolerance, maxIterations);
  if (!out.aim.ok) {
    out.error = out.aim.error;
    return out;
  }
  const int presses = clicks >= 2 ? 2 : 1;
  for (int i = 0; i < presses; ++i) {
    input.Mouse(bit, 0, 0);
    Sleep(60);
    input.Mouse(0, 0, 0);
    Sleep(presses > 1 && i + 1 < presses ? 80 : 120);
  }
  out.ok = true;
  return out;
}

ClickOutcome DragLivePointer(const LiveInputWriter &input,
                             const std::wstring &shmName, int x1, int y1,
                             int x2, int y2, int button, int tolerance,
                             int maxIterations) {
  ClickOutcome out;
  const uint8_t bit = button == 1 ? 0x02u : (button == 2 ? 0x04u : 0x01u);
  out.aim = AimLivePointer(input, shmName, x1, y1, 0, tolerance, maxIterations);
  if (!out.aim.ok) {
    out.error = out.aim.error;
    return out;
  }
  input.Mouse(bit, 0, 0); // press
  Sleep(80);
  const AimOutcome move =
      AimLivePointer(input, shmName, x2, y2, bit, tolerance, maxIterations);
  input.Mouse(0, 0, 0); // always release, even when the drag lost the pointer
  Sleep(120);
  if (!move.ok) {
    out.error = move.error;
    return out;
  }
  out.ok = true;
  return out;
}

// ---- Input ownership (actuator lease) ---------------------------------------

namespace {

// Shared-lease record + named mutex. The record is tiny and rewritten in place
// under the mutex; readers always see a consistent owner/generation pair.
struct SharedLeaseRecord {
  std::string owner;
  uint64_t generation = 0;
};

std::wstring LeaseMutexName(const std::filesystem::path &path) {
  const std::string text = PathToUtf8(path);
  uint64_t hash = 1469598103934665603ull;
  for (char c : text) {
    hash ^= static_cast<uint8_t>(c);
    hash *= 1099511628211ull;
  }
  wchar_t buf[64]{};
  _snwprintf_s(buf, _TRUNCATE, L"Local\\AntiMalInputLease_%016llX",
               static_cast<unsigned long long>(hash));
  return buf;
}

class NamedLeaseLock {
public:
  explicit NamedLeaseLock(const std::filesystem::path &path)
      : name_(LeaseMutexName(path)) {
    handle_ = CreateMutexW(nullptr, FALSE, name_.c_str());
    if (handle_ != nullptr) {
      WaitForSingleObject(handle_, 15000);
    }
  }
  ~NamedLeaseLock() {
    if (handle_ != nullptr) {
      ReleaseMutex(handle_);
      CloseHandle(handle_);
    }
  }
  NamedLeaseLock(const NamedLeaseLock &) = delete;
  NamedLeaseLock &operator=(const NamedLeaseLock &) = delete;

private:
  std::wstring name_;
  HANDLE handle_ = nullptr;
};

SharedLeaseRecord ReadSharedLease(const std::filesystem::path &path) {
  SharedLeaseRecord record;
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return record;
  }
  uint32_t magic = 0;
  uint64_t generation = 0;
  uint32_t length = 0;
  in.read(reinterpret_cast<char *>(&magic), sizeof(magic));
  in.read(reinterpret_cast<char *>(&generation), sizeof(generation));
  in.read(reinterpret_cast<char *>(&length), sizeof(length));
  if (magic != 0x4C4C4D41u /*'AMLL'*/ || length > 64) {
    return record; // unreadable or foreign: treat as unowned
  }
  record.owner.assign(length, '\0');
  if (length > 0) {
    in.read(record.owner.data(), static_cast<std::streamsize>(length));
    if (!in) {
      record.owner.clear();
      return record;
    }
  }
  record.generation = generation;
  return record;
}

void WriteSharedLease(const std::filesystem::path &path,
                      const SharedLeaseRecord &record) {
  const std::filesystem::path temp = path.wstring() + L".tmp";
  {
    std::ofstream out(temp, std::ios::binary | std::ios::trunc);
    if (!out) {
      return;
    }
    const uint32_t magic = 0x4C4C4D41u;
    const uint32_t length = static_cast<uint32_t>(record.owner.size());
    out.write(reinterpret_cast<const char *>(&magic), sizeof(magic));
    out.write(reinterpret_cast<const char *>(&record.generation),
              sizeof(record.generation));
    out.write(reinterpret_cast<const char *>(&length), sizeof(length));
    if (length > 0) {
      out.write(record.owner.data(), static_cast<std::streamsize>(length));
    }
    if (!out) {
      std::error_code ec;
      std::filesystem::remove(temp, ec);
      return;
    }
  }
  std::error_code ec;
  std::filesystem::rename(temp, path, ec);
  if (ec) {
    std::filesystem::remove(path, ec);
    std::filesystem::rename(temp, path, ec);
  }
}

} // namespace

LiveInputLease::LiveInputLease(std::filesystem::path sharedPath)
    : sharedPath_(std::move(sharedPath)) {}

bool LiveInputLease::Acquire(const std::string &owner) {
  if (sharedPath_.empty()) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!owner_.empty() && owner_ != owner) {
      return false;
    }
    if (owner_ != owner) {
      owner_ = owner;
      ++generation_;
    }
    return true;
  }
  NamedLeaseLock lock(sharedPath_);
  SharedLeaseRecord record = ReadSharedLease(sharedPath_);
  if (!record.owner.empty() && record.owner != owner) {
    return false;
  }
  if (record.owner != owner) {
    record.owner = owner;
    record.generation += 1;
    WriteSharedLease(sharedPath_, record);
  }
  return true;
}

void LiveInputLease::Release(const std::string &owner) {
  if (sharedPath_.empty()) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (owner_ == owner) {
      owner_.clear();
      ++generation_;
    }
    return;
  }
  NamedLeaseLock lock(sharedPath_);
  SharedLeaseRecord record = ReadSharedLease(sharedPath_);
  if (record.owner == owner) {
    record.owner.clear();
    record.generation += 1;
    WriteSharedLease(sharedPath_, record);
  }
}

std::string LiveInputLease::TakeOver(const std::string &newOwner) {
  if (sharedPath_.empty()) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string previous = owner_;
    if (previous != newOwner) {
      owner_ = newOwner;
      ++generation_;
    }
    return previous;
  }
  NamedLeaseLock lock(sharedPath_);
  SharedLeaseRecord record = ReadSharedLease(sharedPath_);
  const std::string previous = record.owner;
  if (previous != newOwner) {
    record.owner = newOwner;
    record.generation += 1;
    WriteSharedLease(sharedPath_, record);
  }
  return previous;
}

bool LiveInputLease::Holds(const std::string &owner) const {
  if (sharedPath_.empty()) {
    std::lock_guard<std::mutex> lock(mutex_);
    return !owner_.empty() && owner_ == owner;
  }
  NamedLeaseLock lock(sharedPath_);
  const SharedLeaseRecord record = ReadSharedLease(sharedPath_);
  return !record.owner.empty() && record.owner == owner;
}

std::string LiveInputLease::Owner() const {
  if (sharedPath_.empty()) {
    std::lock_guard<std::mutex> lock(mutex_);
    return owner_;
  }
  NamedLeaseLock lock(sharedPath_);
  return ReadSharedLease(sharedPath_).owner;
}

uint64_t LiveInputLease::Generation() const {
  if (sharedPath_.empty()) {
    std::lock_guard<std::mutex> lock(mutex_);
    return generation_;
  }
  NamedLeaseLock lock(sharedPath_);
  return ReadSharedLease(sharedPath_).generation;
}

size_t ReleaseHeldGuestInput(const LiveInputWriter &input,
                             const std::vector<uint8_t> &heldKeyScancodes,
                             uint8_t lastMouseButtons) {
  size_t records = 0;
  if (lastMouseButtons != 0) {
    if (input.Mouse(0, 0, 0)) { // release every mouse button
      ++records;
    }
  }
  // Entries are MAKE sequences: a plain Set-1 code (0x2A) or an extended
  // sequence (0xE0, 0x5B). The release must mirror the make's prefix -- the
  // Windows key has no non-extended form, so emitting a bare DB leaves it
  // logically down in the guest.
  for (size_t i = 0; i < heldKeyScancodes.size(); ++i) {
    const uint8_t code = heldKeyScancodes[i];
    if (code == 0 || code >= 0x80) {
      continue; // already a break code or a no-op
    }
    const bool extended = (i > 0 && heldKeyScancodes[i - 1] == 0xE0);
    std::vector<uint8_t> release;
    if (extended) {
      release.push_back(0xE0);
    }
    release.push_back(static_cast<uint8_t>(code | 0x80));
    if (input.KeyScancodes(release)) {
      ++records;
    }
  }
  return records;
}

bool TakeOverInputAsHuman(const std::filesystem::path &liveInputFile) {
  LiveInputLease lease(liveInputFile.parent_path() / kInputLeaseFileName);
  lease.TakeOver("human");
  const LiveInputWriter releaseWriter{liveInputFile};
  // Release every modifier a previous actuator may have left held, including
  // the EXTENDED variants (right Ctrl/Alt and both Windows keys): the Windows
  // key has no plain break form, so it must be released as E0 DB/E0 DC.
  ReleaseHeldGuestInput(
      releaseWriter,
      {0x2A, 0x1D, 0x38, 0xE0, 0x1D, 0xE0, 0x38, 0xE0, 0x5B, 0xE0, 0x5C},
      0x07);
  return true;
}

} // namespace antimal