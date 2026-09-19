// VmInput.cpp - the CLI half of the live host->guest input channel.
//
// A detonation started with ANTIMAL_LIVE_INPUT=<file> tails that file for framed
// keyboard/mouse records (antimal/hv/LiveInputProtocol.h) and injects them into
// the guest's PS/2 controller. This command APPENDS records, which is how the
// agent (or the analyst driving the run from a script) can interact with a
// running detonation: answer installer dialogs, type into fields, click buttons,
// open the Run box, and so on.
//
// Examples:
//   antimal vminput --file C:\AntiMalRuns\_demo\live.bin --key Enter
//   antimal vminput --file live.bin --text "hello world" --delay 40
//   antimal vminput --file live.bin --chord alt+f4
//   antimal vminput --file live.bin --mouse 120,-60,1 --mouse -120,60,0
//   (--mouse deltas are SCREEN-space: x right, y down.)
#include <windows.h>

#include "antimal/LiveVm.h"
#include "antimal/hv/LiveInputProtocol.h"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace {

bool AppendBytes(const std::wstring &path, const std::vector<uint8_t> &bytes) {
  if (bytes.empty()) {
    return true;
  }
  HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                         OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) {
    std::fprintf(stderr, "vminput: cannot open %ls (error %lu)\n", path.c_str(),
                 GetLastError());
    return false;
  }
  DWORD written = 0;
  const BOOL ok = WriteFile(h, bytes.data(), static_cast<DWORD>(bytes.size()),
                            &written, nullptr);
  FlushFileBuffers(h);
  CloseHandle(h);
  if (!ok || written != bytes.size()) {
    std::fprintf(stderr, "vminput: write failed (error %lu)\n", GetLastError());
    return false;
  }
  return true;
}

bool NamedKeyTap(const std::string &name, std::vector<uint8_t> *out) {
  // Single source of truth: Common's key table (shared with ChordScancodes).
  return antimal::NamedKeyScancodes(name, out);
}

// Chord like "ctrl+shift+esc", "alt+f4", "win+r": hold the modifiers, tap the
// final key, release the modifiers (modifier make/release around the tap).
// Delegates to Common's encoder: the previous local copy here had the SAME
// flat-reverse defect (the Windows key released as DB E0) but was not covered
// by the LiveVm unit tests, so the CLI still emitted malformed releases.
bool ChordTap(const std::string &spec, std::vector<uint8_t> *out) {
  return antimal::ChordScancodes(spec, out);
}

std::wstring ArgVal(int argc, wchar_t **argv, int i) {
  return (i + 1 < argc) ? std::wstring(argv[i + 1]) : std::wstring();
}

std::string Narrow(const std::wstring &w) {
  if (w.empty()) {
    return {};
  }
  const int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0,
                                    nullptr, nullptr);
  std::string s(n > 0 ? n - 1 : 0, '\0');
  if (n > 1) {
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), n, nullptr,
                        nullptr);
  }
  return s;
}

} // namespace

int CommandVmInput(int argc, wchar_t **argv) {
  std::wstring file;
  int delayMs = 60;
  bool any = false;
  bool ok = true;

  for (int i = 2; i < argc; ++i) {
    const std::wstring arg = argv[i];
    if (arg == L"--file") {
      file = ArgVal(argc, argv, i);
      ++i;
      continue;
    }
    if (arg == L"--delay") {
      delayMs = _wtoi(ArgVal(argc, argv, i).c_str());
      ++i;
      continue;
    }
    if (arg == L"--text") {
      const std::string text = Narrow(ArgVal(argc, argv, i));
      ++i;
      for (char ch : text) {
        const auto tap = antimal::hv::AsciiToSet1Tap(ch);
        if (tap.empty()) {
          continue;
        }
        ok = AppendBytes(file, antimal::hv::EncodeKeyRecords(tap)) && ok;
        any = true;
        if (delayMs > 0) {
          Sleep(static_cast<DWORD>(delayMs));
        }
      }
      continue;
    }
    if (arg == L"--key") {
      std::vector<uint8_t> tap;
      if (NamedKeyTap(Narrow(ArgVal(argc, argv, i)), &tap) ||
          (ArgVal(argc, argv, i).size() == 1 &&
           (tap = antimal::hv::AsciiToSet1Tap(
                static_cast<char>(ArgVal(argc, argv, i)[0])),
            !tap.empty()))) {
        ok = AppendBytes(file, antimal::hv::EncodeKeyRecords(tap)) && ok;
        any = true;
      } else {
        std::fprintf(stderr, "vminput: unknown key\n");
        ok = false;
      }
      ++i;
      if (delayMs > 0) {
        Sleep(static_cast<DWORD>(delayMs));
      }
      continue;
    }
    if (arg == L"--chord") {
      std::vector<uint8_t> tap;
      if (ChordTap(Narrow(ArgVal(argc, argv, i)), &tap)) {
        ok = AppendBytes(file, antimal::hv::EncodeKeyRecords(tap)) && ok;
        any = true;
      } else {
        std::fprintf(stderr, "vminput: bad chord\n");
        ok = false;
      }
      ++i;
      if (delayMs > 0) {
        Sleep(static_cast<DWORD>(delayMs));
      }
      continue;
    }
    if (arg == L"--mouse") {
      const std::string spec = Narrow(ArgVal(argc, argv, i));
      int dx = 0, dy = 0, buttons = 0;
      const int n = std::sscanf(spec.c_str(), "%d,%d,%d", &dx, &dy, &buttons);
      if (n >= 2) {
        // SCREEN-space convention (x right, y down) -- same as `vmmouse` and
        // the webui. The encoder flips Y once and splits displacements beyond
        // the signed-8-bit PS/2 packet limit, so large moves no longer wrap.
        const auto rec = antimal::hv::EncodeMouseScreenMoveRecords(
            static_cast<uint8_t>(buttons), dx, dy);
        ok = AppendBytes(file, rec) && ok;
        any = true;
      } else {
        std::fprintf(stderr, "vminput: bad mouse spec\n");
        ok = false;
      }
      ++i;
      if (delayMs > 0) {
        Sleep(static_cast<DWORD>(delayMs));
      }
      continue;
    }
  }

  // Operator input is a HUMAN TAKEOVER: it claims actuator ownership in the
  // shared lease (so a queued assistant action is denied at delivery time) and
  // releases anything an agent may have left held (buttons/modifiers).
  if (!file.empty()) {
    antimal::LiveInputLease lease(
        std::filesystem::path(file).parent_path() /
        antimal::kInputLeaseFileName);
    lease.TakeOver("human");
    const antimal::LiveInputWriter releaseWriter{std::filesystem::path(file)};
    antimal::ReleaseHeldGuestInput(releaseWriter, {0x2A, 0x1D, 0x38}, 0x07);
  }

  if (file.empty() || !any) {
    std::fprintf(stderr,
                 "usage: antimal vminput --file <live-input.bin> "
                 "[--text \"...\"] [--key Enter] [--chord alt+f4] "
                 "[--mouse dx,dy[,buttons]] [--delay ms]\n"
                 "  --mouse is SCREEN-space (x right, y down), matching vmmouse;\n"
                 "  large deltas are split into valid PS/2 packets, not wrapped.\n");
    return 2;
  }
  return ok ? 0 : 1;
}
