// VmTools.cpp - the CLI half of coordinate-based live-VM interaction:
// vmstatus / vmframe / vmmouse.
//
// Thin wrappers over the Common LiveVm layer so an operator (or an agent that
// cannot speak MCP) can still drive and witness the live session the GUI is
// showing. The closed loop is the same code the MCP tools use -- probe, learn
// the cursor, step, measure, correct -- so a click here is a click there.
#include "antimal/Config.h"
#include "antimal/FileUtil.h"
#include "antimal/LiveVm.h"

#include <windows.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace {

std::wstring OptValue(int argc, wchar_t **argv, const wchar_t *name) {
  for (int i = 2; i + 1 < argc; ++i) {
    if (std::wcscmp(argv[i], name) == 0) {
      return argv[i + 1];
    }
  }
  return std::wstring();
}

bool HasArg(int argc, wchar_t **argv, const wchar_t *name) {
  for (int i = 2; i < argc; ++i) {
    if (std::wcscmp(argv[i], name) == 0) {
      return true;
    }
  }
  return false;
}

std::string JsonQuote(const std::string &s) {
  std::string o = "\"";
  for (char c : s) {
    switch (c) {
    case '\\': o += "\\\\"; break;
    case '"': o += "\\\""; break;
    case '\n': o += "\\n"; break;
    case '\r': o += "\\r"; break;
    case '\t': o += "\\t"; break;
    default:
      if (static_cast<unsigned char>(c) < 0x20) {
        char buf[8];
        std::snprintf(buf, sizeof(buf), "\\u%04x",
                      static_cast<unsigned int>(static_cast<unsigned char>(c)));
        o += buf;
      } else {
        o += c;
      }
    }
  }
  return o + "\"";
}

std::string Stamp() {
  SYSTEMTIME st{};
  GetLocalTime(&st);
  char buf[64];
  std::snprintf(buf, sizeof(buf), "%04d%02d%02d-%02d%02d%02d-%03d", st.wYear,
                st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                st.wMilliseconds);
  return buf;
}

std::filesystem::path WorkspaceRoot() {
  return antimal::LoadConfig(antimal::DefaultConfigPath()).workspaceRoot;
}

std::string AimJson(const antimal::AimOutcome &a) {
  char buf[256];
  std::snprintf(buf, sizeof(buf),
                "\"cursor\":{\"x\":%d,\"y\":%d},\"finalError\":{\"x\":%d,"
                "\"y\":%d},\"iterations\":%d,\"learned\":%s",
                a.cursorX, a.cursorY, a.errorX, a.errorY, a.iterations,
                a.learned ? "true" : "false");
  return buf;
}

} // namespace

namespace {

// True while some process holds the run's exclusive run.lock (i.e. a live
// worker owns this run). Opening with share=0 fails with ERROR_SHARING_VIOLATION
// when the worker is alive; anything else means no live worker.
bool RunLockHeld(const std::filesystem::path &runDir) {
  const std::filesystem::path lock = runDir / L"run.lock";
  HANDLE h = CreateFileW(lock.c_str(), GENERIC_READ, 0 /*no share*/, nullptr,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h != INVALID_HANDLE_VALUE) {
    CloseHandle(h);
    return false;
  }
  return GetLastError() == ERROR_SHARING_VIOLATION;
}

} // namespace

// antimal vmfinalize [<run-id>] [--wait] [--timeout-sec N] [--json]
//
// Graceful stop for a live session: drops `<runDir>\finalize.request`, which the
// run loop notices on its next progress tick and exits through the NORMAL
// report-writing path. This is deliberately different from killing the worker
// (which loses the scored verdict): the run ends with report.json finalized.
int CommandVmFinalize(int argc, wchar_t **argv) {
  const std::wstring explicitId = OptValue(argc, argv, L"--run");
  const std::filesystem::path ws = WorkspaceRoot();
  std::filesystem::path runDir;

  // Positional run id (or path) and --run are equivalent.
  std::wstring id = explicitId;
  if (id.empty()) {
    for (int i = 2; i < argc; ++i) {
      const std::wstring a = argv[i];
      if (a.rfind(L"--", 0) == 0) {
        continue;
      }
      id = a;
      break;
    }
  }
  if (!id.empty()) {
    std::filesystem::path candidate(id);
    if (std::filesystem::is_directory(candidate)) {
      runDir = candidate;
    } else {
      runDir = ws / id;
    }
  } else {
    const antimal::LiveRun newest = antimal::FindNewestRun(ws);
    runDir = newest.dir;
  }
  if (runDir.empty() || !std::filesystem::is_directory(runDir)) {
    if (HasArg(argc, argv, L"--json")) {
      std::cout << "{\"ok\":false,\"error\":\"no run directory found\"}\n";
    } else {
      std::cerr << "vmfinalize: no run directory found (pass a run id or boot "
                   "a session first)\n";
    }
    return 2;
  }

  const bool wasLive = RunLockHeld(runDir);
  std::error_code ec;
  const std::filesystem::path marker = runDir / L"finalize.request";
  {
    std::ofstream out(marker, std::ios::binary | std::ios::trunc);
    out << "requested=hostcli-vmfinalize\n";
  }
  if (!std::filesystem::exists(marker, ec)) {
    std::cerr << "vmfinalize: could not write " << antimal::PathToUtf8(marker)
              << "\n";
    return 1;
  }

  const bool wait = HasArg(argc, argv, L"--wait");
  int waitSec = 120;
  if (const std::wstring v = OptValue(argc, argv, L"--timeout-sec");
      !v.empty()) {
    waitSec = _wtoi(v.c_str());
    if (waitSec <= 0) {
      waitSec = 120;
    }
  }
  bool finalized = false;
  if (wait) {
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(waitSec);
    while (std::chrono::steady_clock::now() < deadline) {
      if (!RunLockHeld(runDir)) {
        break;
      }
      Sleep(250);
    }
    finalized = std::filesystem::exists(runDir / L"report.json", ec);
  }

  if (HasArg(argc, argv, L"--json")) {
    std::cout << "{\"ok\":true,\"runDir\":"
              << JsonQuote(antimal::PathToUtf8(runDir))
              << ",\"wasLive\":" << (wasLive ? "true" : "false")
              << ",\"waited\":" << (wait ? "true" : "false")
              << ",\"reportJson\":"
              << (std::filesystem::exists(runDir / L"report.json", ec)
                      ? "true"
                      : "false")
              << "}\n";
    return 0;
  }
  std::cout << "finalize requested for " << antimal::PathToUtf8(runDir)
            << (wasLive ? " (live worker)" : " (no live worker detected)")
            << "\n";
  if (wait) {
    std::cout << (finalized ? "run finalized: report.json written\n"
                            : "waited, but report.json has not appeared yet\n");
  }
  return 0;
}

// antimal vmstatus [--json]
int CommandVmStatus(int argc, wchar_t **argv) {
  const antimal::AppConfig cfg = antimal::LoadConfig(antimal::DefaultConfigPath());
  const antimal::LiveVmStatus s = antimal::QueryLiveVmStatus(cfg, 400);
  if (HasArg(argc, argv, L"--json")) {
    std::cout << "{\"liveFramePresent\":" << (s.framePresent ? "true" : "false")
              << ",\"width\":" << s.width << ",\"height\":" << s.height
              << ",\"frameSeq\":" << s.frameSeq
              << ",\"frameAdvancing\":" << (s.frameAdvancing ? "true" : "false")
              << ",\"fps\":" << s.fps
              << ",\"blank\":" << (s.blank ? "true" : "false")
              << ",\"inputFileBytes\":" << s.inputFileBytes
              << ",\"newestRun\":"
              << JsonQuote(s.run.dir.empty() ? std::string()
                                             : antimal::PathToUtf8(s.run.dir))
              << ",\"eventsJsonl\":"
              << (s.run.HasJournal() ? "true" : "false")
              << ",\"reportJson\":"
              << (std::filesystem::exists(s.run.reportJson) ? "true" : "false")
              << ",\"hostCliProcesses\":" << s.hostCliProcesses.size()
              << "}\n";
    return 0;
  }
  if (!s.framePresent) {
    std::cout << "live frame : not present (no live VM running)\n";
  } else {
    std::cout << "live frame : " << s.width << "x" << s.height << " seq "
              << s.frameSeq << (s.frameAdvancing ? " (advancing, " : " (stalled, ")
              << s.fps << " fps)" << (s.blank ? " [blank]" : "") << "\n";
  }
  std::cout << "input file : "
            << antimal::PathToUtf8(cfg.workspaceRoot /
                                   antimal::kLiveInputFileName)
            << " (" << s.inputFileBytes << " bytes)\n";
  std::cout << "newest run : "
            << (s.run.dir.empty() ? std::string("(none)")
                                  : antimal::PathToUtf8(s.run.dir))
            << " (events.jsonl "
            << (s.run.HasJournal() ? "yes" : "no") << ", report.json "
            << (std::filesystem::exists(s.run.reportJson) ? "yes" : "no")
            << ")\n";
  std::cout << "host procs : " << s.hostCliProcesses.size() << "\n";
  return s.framePresent ? 0 : 1;
}

// antimal vmframe [--name <shm>] [--out <png>]
int CommandVmFrame(int argc, wchar_t **argv) {
  const std::wstring name = OptValue(argc, argv, L"--name");
  std::wstring out = OptValue(argc, argv, L"--out");
  std::string path;
  if (out.empty()) {
    path = antimal::PathToUtf8(WorkspaceRoot() / L"_mcp" /
                               antimal::Utf8ToWide("shot-" + Stamp() +
                                                   "-frame.png"));
  } else {
    path = antimal::PathToUtf8(out);
  }
  antimal::LiveFrame info;
  std::string err;
  if (!antimal::CaptureLiveFrameToPng(
          name.empty() ? antimal::kLiveFrameShmName : name,
          antimal::Utf8ToWide(path), &info, &err)) {
    std::cerr << "vmframe: " << err << "\n";
    return 1;
  }
  std::cout << path << "\n";
  return 0;
}

// antimal vmmouse --to X,Y [--click] [--double] [--button left|right|middle]
//                  [--file <live-input.bin>] [--shm <name>] [--tolerance N]
int CommandVmMouse(int argc, wchar_t **argv) {
  const std::wstring to = OptValue(argc, argv, L"--to");
  int x = 0, y = 0;
  if (to.empty() || std::swscanf(to.c_str(), L"%d,%d", &x, &y) != 2 ||
      x < 0 || y < 0) {
    std::cerr << "usage: antimal vmmouse --to X,Y [--click] [--double] "
                 "[--button left|right|middle] [--file live.bin] [--shm name]\n";
    return 2;
  }
  int button = 0;
  const std::wstring buttonName = OptValue(argc, argv, L"--button");
  if (buttonName == L"right") {
    button = 1;
  } else if (buttonName == L"middle") {
    button = 2;
  }
  const int tolerance = _wtoi(OptValue(argc, argv, L"--tolerance").c_str());
  std::wstring file = OptValue(argc, argv, L"--file");
  if (file.empty()) {
    file = (WorkspaceRoot() / antimal::kLiveInputFileName).wstring();
  }
  const std::wstring shm = OptValue(argc, argv, L"--shm");
  const std::wstring shmName =
      shm.empty() ? std::wstring(antimal::kLiveFrameShmName) : shm;

  // Coordinate input from a person is a HUMAN TAKEOVER of actuator ownership:
  // a queued assistant action is denied when it reaches the wire, and anything
  // an agent left held is released before this pointer starts moving.
  {
    antimal::LiveInputLease lease(
        std::filesystem::path(file).parent_path() /
        antimal::kInputLeaseFileName);
    lease.TakeOver("human");
    const antimal::LiveInputWriter releaseWriter{file};
    antimal::ReleaseHeldGuestInput(releaseWriter, {0x2A, 0x1D, 0x38}, 0x07);
  }

  const antimal::LiveInputWriter input(file);
  const int tol = tolerance > 0 ? tolerance : 4;
  std::string out;
  if (HasArg(argc, argv, L"--click")) {
    const antimal::ClickOutcome r = antimal::ClickLivePointer(
        input, shmName, x, y, button,
        HasArg(argc, argv, L"--double") ? 2 : 1, tol);
    out = std::string("{\"ok\":") + (r.ok ? "true" : "false") +
          ",\"error\":" + JsonQuote(r.error) + "," + AimJson(r.aim) + "}";
  } else {
    const antimal::AimOutcome a =
        antimal::AimLivePointer(input, shmName, x, y, 0, tol);
    out = std::string("{\"ok\":") + (a.ok ? "true" : "false") +
          ",\"error\":" + JsonQuote(a.error) + "," + AimJson(a) + "}";
  }
  std::cout << out << "\n";
  return out.find("\"ok\":true") != std::string::npos ? 0 : 1;
}
