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
#include <windows.h>

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
  std::string lower;
  for (char c : name) {
    lower.push_back(static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c));
  }
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
bool ChordTap(const std::string &spec, std::vector<uint8_t> *out) {
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
  std::vector<uint8_t> breaks;
  for (size_t i = 0; i + 1 < parts.size(); ++i) {
    std::string m;
    for (char c : parts[i]) {
      m.push_back(static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c));
    }
    if (m == "ctrl" || m == "control") {
      makes.push_back(0x1D);
      breaks.push_back(0x9D);
    } else if (m == "alt") {
      makes.push_back(0x38);
      breaks.push_back(0xB8);
    } else if (m == "shift") {
      makes.push_back(0x2A);
      breaks.push_back(0xAA);
    } else if (m == "win" || m == "meta") {
      makes.push_back(0xE0);
      makes.push_back(0x5B);
      breaks.push_back(0xE0);
      breaks.push_back(0xDB);
    } else {
      return false;
    }
  }
  // Tap the final key (named key, or a single ASCII char).
  std::vector<uint8_t> tap;
  const std::string &last = parts.back();
  if (!NamedKeyTap(last, &tap)) {
    if (last.size() == 1) {
      tap = antimal::hv::AsciiToSet1Tap(last[0]);
    }
  }
  if (tap.empty()) {
    return false;
  }
  out->insert(out->end(), makes.begin(), makes.end());
  out->insert(out->end(), tap.begin(), tap.end());
  out->insert(out->end(), breaks.rbegin(), breaks.rend());
  return true;
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
        const auto rec = antimal::hv::EncodeMouseRecord(
            static_cast<uint8_t>(buttons), static_cast<int8_t>(dx),
            static_cast<int8_t>(dy));
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

  if (file.empty() || !any) {
    std::fprintf(stderr,
                 "usage: antimal vminput --file <live-input.bin> "
                 "[--text \"...\"] [--key Enter] [--chord alt+f4] "
                 "[--mouse dx,dy[,buttons]] [--delay ms]\n");
    return 2;
  }
  return ok ? 0 : 1;
}
