// AntiMal.McpServer - the Model Context Protocol (stdio) tool surface that
// lets an agent drive and OBSERVE the live analysis VM.
//
// Why this exists: an agent that only reads report.json is guessing. These
// tools hand the agent the same live session the analyst watches -- boot it,
// screenshot it, move/click at coordinates with a measured aim report, type,
// read the live telemetry journal -- so every conclusion can be tied to a
// frame and an event. The tool descriptions steer that behavior and the
// results carry the evidence (screenshot paths, cursor position, pixel error).
//
// Transport: MCP over stdin/stdout, newline-delimited JSON-RPC 2.0. All
// logging goes to stderr; stdout carries protocol bytes only.
#include "antimal/Config.h"
#include "antimal/EventJournal.h"
#include "antimal/FileUtil.h"
#include "antimal/JsonValue.h"
#include "antimal/LiveVm.h"
#include "antimal/Version.h"
#include "antimal/hv/LiveFrameShm.h"
#include "antimal/hv/LiveInputProtocol.h"

#include <windows.h>

#include <fcntl.h>
#include <io.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

using antimal::JsonValue;

namespace {

// ---- JSON helpers (hand-rolled like HostCli's; no external dependency) ------

std::string JsonQuote(const std::string &s) {
  std::string o = "\"";
  for (char c : s) {
    switch (c) {
    case '\\': o += "\\\\"; break;
    case '"': o += "\\\""; break;
    case '\b': o += "\\b"; break;
    case '\f': o += "\\f"; break;
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
      break;
    }
  }
  return o + "\"";
}

std::string JsonId(const JsonValue &v) {
  if (v.IsString()) {
    return JsonQuote(v.AsString());
  }
  if (v.IsNumber()) {
    if (v.number == static_cast<double>(static_cast<long long>(v.number))) {
      return std::to_string(static_cast<long long>(v.number));
    }
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%.17g", v.number);
    return buf;
  }
  return "null";
}

std::string ArgString(const JsonValue &args, const char *key,
                      const std::string &fallback = std::string()) {
  const JsonValue &v = args.At(key);
  return v.IsString() ? v.AsString() : fallback;
}

int ArgInt(const JsonValue &args, const char *key, int fallback) {
  const JsonValue &v = args.At(key);
  return v.IsNumber() ? static_cast<int>(v.AsNumber()) : fallback;
}

bool ArgBool(const JsonValue &args, const char *key, bool fallback) {
  const JsonValue &v = args.At(key);
  return v.IsBool() ? v.AsBool() : fallback;
}

// ---- Environment helpers ----------------------------------------------------

std::filesystem::path ExeDir() {
  wchar_t buf[MAX_PATH]{};
  GetModuleFileNameW(nullptr, buf, MAX_PATH);
  return std::filesystem::path(buf).parent_path();
}

std::string FileStamp() {
  SYSTEMTIME st{};
  GetLocalTime(&st);
  char buf[64];
  std::snprintf(buf, sizeof(buf), "%04d%02d%02d-%02d%02d%02d-%03d", st.wYear,
                st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                st.wMilliseconds);
  return buf;
}

std::string SanitizeTag(const std::string &tag) {
  std::string out;
  for (char c : tag) {
    out += (std::isalnum(static_cast<unsigned char>(c)) || c == '-') ? c : '-';
  }
  if (out.empty()) {
    out = "shot";
  }
  return out;
}

// <workspace>/_mcp/shot-<stamp>-<tag>.png (the _ prefix keeps it out of
// FindNewestRun's "which run is newest" scan).
std::string NewShotPath(const antimal::AppConfig &cfg, const std::string &tag) {
  const std::filesystem::path p =
      cfg.workspaceRoot / L"_mcp" /
      antimal::Utf8ToWide("shot-" + FileStamp() + "-" + SanitizeTag(tag) + ".png");
  return antimal::PathToUtf8(p);
}

bool SpawnDetached(const std::wstring &command, const std::filesystem::path &cwd,
                   DWORD *pidOut) {
  std::vector<wchar_t> cmdBuf(command.begin(), command.end());
  cmdBuf.push_back(0);
  STARTUPINFOW si{};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi{};
  const BOOL ok =
      CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, FALSE,
                     CREATE_NO_WINDOW, nullptr, cwd.c_str(), &si, &pi);
  if (!ok) {
    return false;
  }
  if (pidOut) {
    *pidOut = pi.dwProcessId;
  }
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  return true;
}

antimal::LiveInputWriter InputFor(const antimal::AppConfig &cfg) {
  // MCP-driven input is a HUMAN-DELEGATED surface: the operator invoked this
  // tool with the assistant lease in mind, so every input call claims the SAME
  // shared lease the GUI/CLI/assistant use. A concurrent assistant action is
  // then denied at delivery time instead of racing this one.
  antimal::LiveInputLease lease(cfg.workspaceRoot / antimal::kInputLeaseFileName);
  lease.TakeOver("mcp");
  return antimal::LiveInputWriter(cfg.workspaceRoot / antimal::kLiveInputFileName);
}

std::string TryScreenshot(const antimal::AppConfig &cfg, const std::string &tag,
                          std::string *error) {
  const std::string path = NewShotPath(cfg, tag);
  antimal::LiveFrame info;
  std::string err;
  if (!antimal::CaptureLiveFrameToPng(antimal::kLiveFrameShmName,
                                      antimal::Utf8ToWide(path), &info, &err)) {
    if (error) {
      *error = err;
    }
    return std::string();
  }
  return path;
}

const char *ButtonName(int button) {
  return button == 1 ? "right" : (button == 2 ? "middle" : "left");
}

int ParseButton(const std::string &name) {
  if (name == "right") return 1;
  if (name == "middle") return 2;
  return 0;
}

// ---- Tool results -----------------------------------------------------------

std::string AimJson(const antimal::AimOutcome &a) {
  std::ostringstream o;
  o << "{\"ok\":" << (a.ok ? "true" : "false")
    << ",\"learned\":" << (a.learned ? "true" : "false")
    << ",\"cursor\":{\"x\":" << a.cursorX << ",\"y\":" << a.cursorY << "}"
    << ",\"finalError\":{\"x\":" << a.errorX << ",\"y\":" << a.errorY << "}"
    << ",\"iterations\":" << a.iterations
    << ",\"error\":" << JsonQuote(a.error) << "}";
  return o.str();
}

std::string ClickJson(const antimal::ClickOutcome &r, const std::string &shot) {
  std::ostringstream o;
  o << "{\"ok\":" << (r.ok ? "true" : "false")
    << ",\"error\":" << JsonQuote(r.error)
    << ",\"aim\":" << AimJson(r.aim);
  if (!shot.empty()) {
    o << ",\"screenshot\":" << JsonQuote(shot);
  }
  o << "}";
  return o.str();
}

std::string TextResult(const std::string &text, bool isError) {
  return std::string("{\"content\":[{\"type\":\"text\",\"text\":") +
         JsonQuote(text) + "}],\"isError\":" + (isError ? "true" : "false") +
         "}";
}

void SendLine(const std::string &line) {
  // MCP stdio framing is newline-delimited: an embedded newline (e.g. a raw
  // multi-line JSON literal) would truncate the message and make clients see
  // invalid JSON. Collapse any raw CR/LF into spaces so every reply is exactly
  // one line.
  std::string framed;
  framed.reserve(line.size());
  for (char c : line) {
    framed.push_back(c == '\n' || c == '\r' ? ' ' : c);
  }
  std::fwrite(framed.data(), 1, framed.size(), stdout);
  std::fputc('\n', stdout);
  std::fflush(stdout);
}

void SendResult(const JsonValue &id, const std::string &resultJson) {
  SendLine("{\"jsonrpc\":\"2.0\",\"id\":" + JsonId(id) +
           ",\"result\":" + resultJson + "}");
}

void SendError(const JsonValue &id, int code, const std::string &message) {
  SendLine("{\"jsonrpc\":\"2.0\",\"id\":" + JsonId(id) +
           ",\"error\":{\"code\":" + std::to_string(code) +
           ",\"message\":" + JsonQuote(message) + "}}");
}

void Log(const std::string &message) {
  std::fprintf(stderr, "[antimal-mcp] %s\n", message.c_str());
}

// ---- Journal helpers --------------------------------------------------------

std::filesystem::path ResolveRunDir(const antimal::AppConfig &cfg,
                                    const std::string &requested) {
  if (!requested.empty()) {
    std::filesystem::path p = antimal::Utf8ToWide(requested);
    if (p.is_absolute()) {
      return p;
    }
    return cfg.workspaceRoot / p;
  }
  return antimal::FindNewestRun(cfg.workspaceRoot).dir;
}

std::vector<std::string> ReadJournalLines(const std::filesystem::path &file) {
  std::vector<std::string> lines;
  std::ifstream in(file, std::ios::binary);
  std::string line;
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    if (!line.empty()) {
      lines.push_back(line);
    }
  }
  return lines;
}

// ---- Tools ------------------------------------------------------------------

std::string ToolVmStatus(const antimal::AppConfig &cfg) {
  const antimal::LiveVmStatus s = antimal::QueryLiveVmStatus(cfg, 400);
  std::ostringstream o;
  o << "{\"liveFramePresent\":" << (s.framePresent ? "true" : "false")
    << ",\"frameSeq\":" << s.frameSeq
    << ",\"width\":" << s.width << ",\"height\":" << s.height
    << ",\"fps\":" << s.fps
    << ",\"frameAdvancing\":" << (s.frameAdvancing ? "true" : "false")
    << ",\"blank\":" << (s.blank ? "true" : "false")
    << ",\"inputFileBytes\":" << s.inputFileBytes
    << ",\"hostCliProcesses\":[";
  for (size_t i = 0; i < s.hostCliProcesses.size(); ++i) {
    if (i) o << ",";
    const bool isVmHost = s.hostCliProcesses[i].commandLine.find(L"detonate") !=
                          std::wstring::npos;
    o << "{\"pid\":" << s.hostCliProcesses[i].pid
      << ",\"detonate\":" << (isVmHost ? "true" : "false") << "}";
  }
  o << "],\"newestRun\":"
    << JsonQuote(s.run.dir.empty() ? std::string()
                                   : antimal::PathToUtf8(s.run.dir))
    << ",\"eventsJsonlExists\":"
    << (s.run.HasJournal() ? "true" : "false")
    << ",\"reportJsonExists\":"
    << (std::filesystem::exists(s.run.reportJson) ? "true" : "false")
    << ",\"workspaceRoot\":"
    << JsonQuote(antimal::PathToUtf8(cfg.workspaceRoot))
    << ",\"shmName\":" << JsonQuote(antimal::WideToUtf8(antimal::kLiveFrameShmName))
    << "}";
  return o.str();
}

std::string ToolVmScreenshot(const antimal::AppConfig &cfg,
                             const JsonValue &args) {
  const std::string requested = ArgString(args, "out");
  std::string path = requested;
  if (path.empty()) {
    path = NewShotPath(cfg, "frame");
  }
  antimal::LiveFrame info;
  std::string err;
  if (!antimal::CaptureLiveFrameToPng(antimal::kLiveFrameShmName,
                                      antimal::Utf8ToWide(path), &info, &err)) {
    return std::string("{\"ok\":false,\"error\":") + JsonQuote(err) +
           "}";
  }
  const bool blank = antimal::hv::LiveFrameIsBlank(
      info.frame.pixels.data(), info.width, info.height, info.width * 4);
  std::ostringstream o;
  o << "{\"ok\":true,\"path\":" << JsonQuote(path)
    << ",\"width\":" << info.width << ",\"height\":" << info.height
    << ",\"frameSeq\":" << info.frameSeq
    << ",\"blank\":" << (blank ? "true" : "false")
    << ",\"note\":\"Inspect the image. Blank/near-uniform means no desktop is "
       "rendering yet.\"}";
  return o.str();
}

std::string ToolVmClick(const antimal::AppConfig &cfg, const JsonValue &args) {
  const int x = ArgInt(args, "x", -1);
  const int y = ArgInt(args, "y", -1);
  if (x < 0 || y < 0) {
    return R"({"ok":false,"error":"x and y are required"})";
  }
  const int button = ParseButton(ArgString(args, "button", "left"));
  const int clicks = ArgInt(args, "clicks", 1) >= 2 ? 2 : 1;
  antimal::LiveInputWriter input = InputFor(cfg);
  const antimal::ClickOutcome r = antimal::ClickLivePointer(
      input, antimal::kLiveFrameShmName, x, y, button, clicks);
  std::string shot;
  if (ArgBool(args, "screenshot", true)) {
    std::string err;
    shot = TryScreenshot(cfg, "after-click", &err);
  }
  return ClickJson(r, shot);
}

std::string ToolVmMove(const antimal::AppConfig &cfg, const JsonValue &args) {
  const int x = ArgInt(args, "x", -1);
  const int y = ArgInt(args, "y", -1);
  if (x < 0 || y < 0) {
    return R"({"ok":false,"error":"x and y are required"})";
  }
  antimal::LiveInputWriter input = InputFor(cfg);
  const antimal::AimOutcome a =
      antimal::AimLivePointer(input, antimal::kLiveFrameShmName, x, y);
  antimal::ClickOutcome r;
  r.ok = a.ok;
  r.aim = a;
  r.error = a.error;
  std::string shot;
  if (ArgBool(args, "screenshot", true)) {
    std::string err;
    shot = TryScreenshot(cfg, "after-move", &err);
  }
  return ClickJson(r, shot);
}

std::string ToolVmDrag(const antimal::AppConfig &cfg, const JsonValue &args) {
  const int x1 = ArgInt(args, "x1", -1);
  const int y1 = ArgInt(args, "y1", -1);
  const int x2 = ArgInt(args, "x2", -1);
  const int y2 = ArgInt(args, "y2", -1);
  if (x1 < 0 || y1 < 0 || x2 < 0 || y2 < 0) {
    return R"({"ok":false,"error":"x1, y1, x2 and y2 are required"})";
  }
  const int button = ParseButton(ArgString(args, "button", "left"));
  antimal::LiveInputWriter input = InputFor(cfg);
  const antimal::ClickOutcome r = antimal::DragLivePointer(
      input, antimal::kLiveFrameShmName, x1, y1, x2, y2, button);
  std::string shot;
  if (ArgBool(args, "screenshot", true)) {
    std::string err;
    shot = TryScreenshot(cfg, "after-drag", &err);
  }
  return ClickJson(r, shot);
}

std::string ToolVmType(const antimal::AppConfig &cfg, const JsonValue &args) {
  const std::string text = ArgString(args, "text");
  if (text.empty()) {
    return R"({"ok":false,"error":"text is required"})";
  }
  const int interval = std::max(0, ArgInt(args, "interval_ms", 30));
  antimal::LiveInputWriter input = InputFor(cfg);
  const bool ok = input.Text(text, interval);
  std::string shot;
  if (ArgBool(args, "screenshot", true)) {
    std::string err;
    shot = TryScreenshot(cfg, "after-type", &err);
  }
  std::ostringstream o;
  o << "{\"ok\":" << (ok ? "true" : "false")
    << ",\"chars\":" << text.size()
    << ",\"error\":" << JsonQuote(ok ? "" : "could not append to live input")
    << ",\"note\":\"Text goes to the focused control -- click the field "
       "first, then screenshot to confirm.\"";
  if (!shot.empty()) {
    o << ",\"screenshot\":" << JsonQuote(shot);
  }
  o << "}";
  return o.str();
}

std::string ToolVmKey(const antimal::AppConfig &cfg, const JsonValue &args) {
  const std::string key = ArgString(args, "key");
  if (key.empty()) {
    return R"({"ok":false,"error":"key is required"})";
  }
  antimal::LiveInputWriter input = InputFor(cfg);
  bool ok = input.NamedKey(key);
  if (!ok && key.size() == 1) {
    const std::vector<uint8_t> tap = antimal::hv::AsciiToSet1Tap(key[0]);
    ok = !tap.empty() && input.KeyScancodes(tap);
  }
  std::string shot;
  if (ArgBool(args, "screenshot", true)) {
    std::string err;
    shot = TryScreenshot(cfg, "after-key", &err);
  }
  std::ostringstream o;
  o << "{\"ok\":" << (ok ? "true" : "false")
    << ",\"key\":" << JsonQuote(key)
    << ",\"error\":" << JsonQuote(ok ? "" : "unknown key name") << "}";
  if (!shot.empty()) {
    o << ",\"screenshot\":" << JsonQuote(shot);
  }
  o << "}";
  return o.str();
}

std::string ToolVmChord(const antimal::AppConfig &cfg, const JsonValue &args) {
  const std::string chord = ArgString(args, "chord");
  if (chord.empty()) {
    return R"({"ok":false,"error":"chord is required"})";
  }
  antimal::LiveInputWriter input = InputFor(cfg);
  const bool ok = input.Chord(chord);
  std::string shot;
  if (ArgBool(args, "screenshot", true)) {
    std::string err;
    shot = TryScreenshot(cfg, "after-chord", &err);
  }
  std::ostringstream o;
  o << "{\"ok\":" << (ok ? "true" : "false")
    << ",\"chord\":" << JsonQuote(chord)
    << ",\"error\":"
    << JsonQuote(ok ? "" : "bad chord spec (ctrl|alt|shift|win + a key)")
    << "}";
  if (!shot.empty()) {
    o << ",\"screenshot\":" << JsonQuote(shot);
  }
  o << "}";
  return o.str();
}

std::string ToolVmEvents(const antimal::AppConfig &cfg, const JsonValue &args) {
  const std::string requested = ArgString(args, "run");
  const std::filesystem::path dir = ResolveRunDir(cfg, requested);
  const std::filesystem::path journal = dir / L"events.jsonl";
  if (dir.empty() || !std::filesystem::exists(journal)) {
    return std::string("{\"ok\":false,\"run\":") +
           JsonQuote(dir.empty() ? std::string() : antimal::PathToUtf8(dir)) +
           ",\"error\":\"no events.jsonl for this run yet\"}";
  }
  const std::vector<std::string> lines = ReadJournalLines(journal);
  const int since = std::max(0, ArgInt(args, "since_line", 0));
  const int limit = std::max(1, ArgInt(args, "limit", 200));
  const std::string filter = ArgString(args, "filter");
  std::ostringstream o;
  o << "{\"ok\":true,\"run\":" << JsonQuote(antimal::PathToUtf8(dir))
    << ",\"totalLines\":" << lines.size() << ",\"sinceLine\":" << since
    << ",\"lines\":[";
  int emitted = 0;
  size_t next = static_cast<size_t>(since);
  for (size_t i = static_cast<size_t>(since);
       i < lines.size() && emitted < limit; ++i) {
    next = i + 1;
    if (!filter.empty() &&
        lines[i].find(filter) == std::string::npos) {
      continue;
    }
    if (emitted) {
      o << ",";
    }
    o << JsonQuote(lines[i]);
    ++emitted;
  }
  o << "],\"nextLine\":" << next
    << ",\"note\":\"Raw journal lines (JSON objects). Sample behavior evidence "
       "lives here, not in a verdict label.\"}";
  return o.str();
}

std::string ToolVmProcesses(const antimal::AppConfig &cfg,
                            const JsonValue &args) {
  const std::filesystem::path dir =
      ResolveRunDir(cfg, ArgString(args, "run"));
  const std::filesystem::path journal = dir / L"events.jsonl";
  if (dir.empty() || !std::filesystem::exists(journal)) {
    return R"({"ok":false,"error":"no events.jsonl for this run yet"})";
  }
  struct ProcState {
    uint32_t parent = 0;
    std::string image;
    std::string fullPath;
    std::string commandLine;
    std::string user;
    std::string integrity;
    std::string lastAction;
    std::string mitre;
    std::string timestamp;
  };
  std::map<uint32_t, ProcState> procs;
  for (const std::string &line : ReadJournalLines(journal)) {
    const antimal::EventRecord e = antimal::ParseEventJsonLine(line);
    if (e.category != "process" || e.processId == 0) {
      continue;
    }
    ProcState &p = procs[e.processId];
    p.parent = e.parentProcessId;
    if (!e.imagePath.empty()) {
      p.image = e.imagePath;
    }
    if (!e.fullImagePath.empty()) {
      p.fullPath = e.fullImagePath;
    }
    if (!e.commandLine.empty()) {
      p.commandLine = e.commandLine;
    }
    if (!e.userName.empty()) {
      p.user = e.userName;
    }
    if (!e.integrityLevel.empty()) {
      p.integrity = e.integrityLevel;
    }
    if (!e.mitre.empty()) {
      p.mitre = e.mitre;
    }
    p.lastAction = e.action;
    p.timestamp = e.timestampUtc;
  }
  std::ostringstream o;
  o << "{\"ok\":true,\"run\":" << JsonQuote(antimal::PathToUtf8(dir))
    << ",\"processes\":[";
  bool first = true;
  for (const auto &[pid, p] : procs) {
    if (!first) {
      o << ",";
    }
    first = false;
    o << "{\"pid\":" << pid << ",\"parentPid\":" << p.parent
      << ",\"image\":" << JsonQuote(p.image)
      << ",\"fullPath\":" << JsonQuote(p.fullPath)
      << ",\"commandLine\":" << JsonQuote(p.commandLine)
      << ",\"user\":" << JsonQuote(p.user)
      << ",\"integrity\":" << JsonQuote(p.integrity)
      << ",\"lastAction\":" << JsonQuote(p.lastAction)
      << ",\"mitre\":" << JsonQuote(p.mitre)
      << ",\"lastEventUtc\":" << JsonQuote(p.timestamp) << "}";
  }
  o << "],\"count\":" << procs.size()
    << ",\"note\":\"Derived from the live journal; lastAction is the newest "
       "observed state for each PID.\"}";
  return o.str();
}

// Depth-first search for the first value under `key` anywhere in the tree.
const JsonValue *FindKey(const JsonValue &v, const std::string &key) {
  if (v.IsObject()) {
    auto it = v.object.find(key);
    if (it != v.object.end()) {
      return &it->second;
    }
    for (const auto &[k, child] : v.object) {
      (void)k;
      if (const JsonValue *found = FindKey(child, key)) {
        return found;
      }
    }
  } else if (v.IsArray()) {
    for (const JsonValue &child : v.array) {
      if (const JsonValue *found = FindKey(child, key)) {
        return found;
      }
    }
  }
  return nullptr;
}

std::string FindKeyText(const JsonValue &root, const std::string &key) {
  const JsonValue *v = FindKey(root, key);
  if (!v) {
    return std::string();
  }
  if (v->IsString()) {
    return v->AsString();
  }
  if (v->IsNumber()) {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%.10g", v->number);
    return buf;
  }
  if (v->IsBool()) {
    return v->AsBool() ? "true" : "false";
  }
  return std::string();
}

std::string ToolVmReport(const antimal::AppConfig &cfg, const JsonValue &args) {
  const std::filesystem::path dir = ResolveRunDir(cfg, ArgString(args, "run"));
  if (dir.empty()) {
    return R"({"ok":false,"error":"no runs under the workspace root"})";
  }
  const std::filesystem::path report = dir / L"report.json";
  std::ostringstream o;
  o << "{\"ok\":true,\"run\":" << JsonQuote(antimal::PathToUtf8(dir));
  if (!std::filesystem::exists(report)) {
    o << ",\"reportExists\":false,\"note\":\"report.json appears only after "
         "the run completes. While the VM is live use vm_screenshot / "
         "vm_events / vm_processes; do not guess a verdict.\"}";
    return o.str();
  }
  const std::string text = antimal::ReadTextFile(report);
  const auto parsed = antimal::ParseJson(text);
  o << ",\"reportExists\":true,\"path\":"
    << JsonQuote(antimal::PathToUtf8(report));
  if (!parsed) {
    o << ",\"parseError\":true}";
    return o.str();
  }
  // Surface the decision fields AND their rationale; the rationale is what an
  // analyst (or agent) must be able to defend.
  const char *keys[] = {"runId",          "sandboxVerdict", "verdictScore",
                        "samplePath",     "sampleExecuted", "guestAgentConnected",
                        "screenStateReached", "timeout",     "sha256",
                        "tags",           "verdictRationale"};
  for (const char *k : keys) {
    const std::string v = FindKeyText(*parsed, k);
    if (!v.empty()) {
      o << "," << JsonQuote(k) << ":" << JsonQuote(v);
    }
  }
  o << "}";
  return o.str();
}

std::string ToolVmBoot(const antimal::AppConfig &cfg, const JsonValue &args) {
  using namespace antimal;
  const std::filesystem::path dir = ExeDir();
  const std::filesystem::path hostCli = dir / L"AntiMal.HostCli.exe";
  const std::filesystem::path agent = dir / L"AntiMal.GuestAgent.exe";
  if (!std::filesystem::exists(hostCli)) {
    return R"({"ok":false,"error":"AntiMal.HostCli.exe is not next to the MCP server"})";
  }
  const LiveFrame probe = ReadLiveFrame(kLiveFrameShmName);
  if (probe.present) {
    return R"({"ok":false,"error":"a live VM is already running; call vm_stop first"})";
  }
  std::string sample = ArgString(args, "sample");
  std::filesystem::path samplePath =
      sample.empty() ? (dir / L"AntiMal.Tests.exe")
                     : std::filesystem::path(Utf8ToWide(sample));
  if (!std::filesystem::exists(samplePath)) {
    return std::string("{\"ok\":false,\"error\":") +
           JsonQuote("sample not found: " + antimal::PathToUtf8(samplePath)) +
           "}";
  }
  // timeout_sec semantics: 0 (the default) is the genuine until-stopped policy
  // -- the VM keeps running until an explicit vm_finalize/vm_stop. No huge
  // stand-in timeout. A positive value is an optional automatic budget; it is
  // not the session lifetime.
  const int timeoutSec = ArgInt(args, "timeout_sec", 0);
  if (timeoutSec < 0) {
    return R"({"ok":false,"error":"timeout_sec must be 0 (until stopped) or a positive number of seconds"})";
  }
  const bool exec = ArgBool(args, "allow_execution", false);
  const bool view = ArgBool(args, "view", true);

  std::filesystem::path seed =
      cfg.workspaceRoot / L"_base" / L"AntiMalDesktop.cow";
  // Preserve an explicit operator-selected retained snapshot. The orchestrator
  // copies it into a new run; silently substituting the desktop loses the
  // installed application and makes subsequent workflow claims invalid.
  const DWORD seedChars = GetEnvironmentVariableW(L"ANTIMAL_SEED_OVERLAY", nullptr, 0);
  if (seedChars) {
    std::wstring selected(seedChars, L'\0');
    const DWORD copied = GetEnvironmentVariableW(L"ANTIMAL_SEED_OVERLAY", selected.data(), seedChars);
    if (!copied || copied >= seedChars) {
      return R"({"ok":false,"error":"Could not read explicit seed overlay"})";
    }
    selected.resize(copied); seed = selected;
    std::error_code seedError;
    if (!std::filesystem::is_regular_file(seed, seedError)) {
      return R"({"ok":false,"error":"Explicit seed overlay is not a readable file; refusing fallback"})";
    }
  }
  const std::filesystem::path liveInput =
      cfg.workspaceRoot / kLiveInputFileName;
  std::error_code ec;
  { std::ofstream trunc(liveInput, std::ios::binary | std::ios::trunc); }

  // Channel + boot knobs, matching the GUI's Boot VM (live) recipe
  // (App/src/WebViewHost.cpp vm.boot) so a tool-driven session is the same
  // session the operator sees in the live console.
  SetEnvironmentVariableW(L"ANTIMAL_FIRMWARE_NAME", L"OVMF-debug.fd");
  SetEnvironmentVariableW(L"ANTIMAL_VCPU_COUNT", L"1");
  SetEnvironmentVariableW(L"ANTIMAL_PROBE_CI_POLICY_OFF", L"1");
  SetEnvironmentVariableW(L"ANTIMAL_PROBE_CI_POLICY_OFF_AGGRESSIVE", L"1");
  SetEnvironmentVariableW(L"ANTIMAL_PROBE_BCD_NOINTEGRITYCHECKS", L"1");
  SetEnvironmentVariableW(L"ANTIMAL_PROBE_BCD_LEGACY_CONTEXT", L"1");
  SetEnvironmentVariableW(L"ANTIMAL_PROBE_BCD_HYPERVISOR_LAUNCH_OFF", L"1");
  SetEnvironmentVariableW(L"ANTIMAL_PROBE_SYSTEM_VBS_COMPAT", L"1");
  SetEnvironmentVariableW(L"ANTIMAL_LIVE_INPUT", liveInput.c_str());
  SetEnvironmentVariableW(L"ANTIMAL_LIVE_FRAME_SHM", kLiveFrameShmName);
  const bool seeded = std::filesystem::exists(seed, ec);
  if (seeded) {
    SetEnvironmentVariableW(L"ANTIMAL_SEED_OVERLAY", seed.c_str());
    SetEnvironmentVariableW(L"ANTIMAL_PROBE_OOBE_KEYS", nullptr);
    SetEnvironmentVariableW(L"ANTIMAL_PROBE_OOBE_NOPASSWORD", L"1");
    SetEnvironmentVariableW(L"ANTIMAL_PROBE_DESKTOP_STABILITY", L"1");
    SetEnvironmentVariableW(L"ANTIMAL_PROBE_LOGIN_PASSWORD", nullptr);
    SetEnvironmentVariableW(L"ANTIMAL_PROBE_OOBE_AUTOLOGON", nullptr);
    SetEnvironmentVariableW(L"ANTIMAL_PROBE_PRESS_ENTER_SEC", nullptr);
    SetEnvironmentVariableW(L"ANTIMAL_PROBE_COMPLETE_OOBE", nullptr);
    SetEnvironmentVariableW(L"ANTIMAL_PROBE_RUN_CMD", nullptr);
    if (!exec) {
      SetEnvironmentVariableW(L"ANTIMAL_PROBE_SHELL_CMD", L"1");
    }
  } else {
    SetEnvironmentVariableW(L"ANTIMAL_SEED_OVERLAY", nullptr);
    SetEnvironmentVariableW(L"ANTIMAL_PROBE_OOBE_KEYS", L"250");
    SetEnvironmentVariableW(L"ANTIMAL_PROBE_PRESS_ENTER_SEC", nullptr);
    SetEnvironmentVariableW(L"ANTIMAL_PROBE_LOGIN_PASSWORD", nullptr);
    SetEnvironmentVariableW(L"ANTIMAL_PROBE_COMPLETE_OOBE", nullptr);
    SetEnvironmentVariableW(L"ANTIMAL_PROBE_SHELL_CMD", nullptr);
    SetEnvironmentVariableW(L"ANTIMAL_PROBE_RUN_CMD", nullptr);
  }
  if (exec) {
    if (seeded) {
      // Detonation keeps the authentic guest environment: drop the
      // usability-only knobs a plain interactive boot would set.
      SetEnvironmentVariableW(L"ANTIMAL_PROBE_SHELL_CMD", nullptr);
      SetEnvironmentVariableW(L"ANTIMAL_PROBE_OOBE_NOPASSWORD", nullptr);
      SetEnvironmentVariableW(L"ANTIMAL_PROBE_DESKTOP_STABILITY", nullptr);
    }
    SetEnvironmentVariableW(L"ANTIMAL_FORCE_DYNAMIC_EXEC", L"1");
    SetEnvironmentVariableW(L"ANTIMAL_AUTHORIZE_EXECUTION", L"1");
    SetEnvironmentVariableW(L"ANTIMAL_ARM_GUEST_EXEC", L"1");
    SetEnvironmentVariableW(L"ANTIMAL_DEPLOY_FRESH_AGENT", L"1");
    if (std::filesystem::exists(agent, ec)) {
      SetEnvironmentVariableW(L"ANTIMAL_FRESH_AGENT_PATH", agent.c_str());
    }
  } else {
    SetEnvironmentVariableW(L"ANTIMAL_FORCE_DYNAMIC_EXEC", nullptr);
    SetEnvironmentVariableW(L"ANTIMAL_AUTHORIZE_EXECUTION", nullptr);
    SetEnvironmentVariableW(L"ANTIMAL_ARM_GUEST_EXEC", nullptr);
    SetEnvironmentVariableW(L"ANTIMAL_DEPLOY_FRESH_AGENT", nullptr);
  }

  std::wstring cmd = L"\"" + hostCli.wstring() + L"\" detonate \"" +
                     samplePath.wstring() + L"\" --network disabled "
                     L"--timeout-sec " +
                     std::to_wstring(timeoutSec);
  if (exec) {
    cmd += L" --allow-execution";
  }
  DWORD pid = 0;
  if (!SpawnDetached(cmd, dir, &pid)) {
    return R"({"ok":false,"error":"CreateProcess for detonate failed"})";
  }
  std::string viewNote;
  if (view) {
    DWORD viewPid = 0;
    if (!SpawnDetached(L"\"" + (dir / L"AntiMal.HostCli.exe").wstring() +
                           L"\" vmview",
                       dir, &viewPid)) {
      viewNote = "could not open the vmview window";
    }
  }
  std::ostringstream o;
  o << "{\"ok\":true,\"pid\":" << pid
    << ",\"seeded\":" << (seeded ? "true" : "false")
    << ",\"sample\":" << JsonQuote(antimal::PathToUtf8(samplePath))
    << ",\"allowExecution\":" << (exec ? "true" : "false")
    << ",\"viewOpened\":" << (view && viewNote.empty() ? "true" : "false")
    << ",\"note\":\"Booting. Poll vm_status (frameSeq advancing == painting) "
       "then vm_screenshot. Reaching the desktop can take many minutes; "
       "report what the frames show, not what you expect.\""
    << ",\"viewNote\":" << JsonQuote(viewNote) << "}";
  return o.str();
}

std::string ToolVmView(const antimal::AppConfig &cfg, const JsonValue &args) {
  (void)cfg;
  (void)args;
  const std::filesystem::path dir = ExeDir();
  DWORD pid = 0;
  if (!SpawnDetached(L"\"" + (dir / L"AntiMal.HostCli.exe").wstring() +
                         L"\" vmview",
                     dir, &pid)) {
    return R"({"ok":false,"error":"could not start vmview"})";
  }
  return std::string("{\"ok\":true,\"pid\":") + std::to_string(pid) +
         ",\"note\":\"The live VM window is now open on the operator's "
         "screen; keep every action visible by taking screenshots too.\"}";
}

// Graceful session end: write `<runDir>/finalize.request`, which the live run
// loop detects and exits through the normal report-writing path. This is the
// NORMAL stop for an interactive/AI session; vm_stop is the emergency path.
std::string ToolVmFinalize(const antimal::AppConfig &cfg, const JsonValue &args) {
  using namespace antimal;
  const LiveVmStatus status = QueryLiveVmStatus(cfg, 0);
  LiveRun run = status.run;
  const std::string runArg = ArgString(args, "run");
  if (!runArg.empty()) {
    run.dir = cfg.workspaceRoot / Utf8ToWide(runArg);
    run.reportJson = run.dir / L"report.json";
    run.eventsJsonl = run.dir / L"events.jsonl";
  }
  if (run.dir.empty() || !std::filesystem::is_directory(run.dir)) {
    return R"({"ok":false,"error":"no run directory found; boot a session or pass run=<id>"})";
  }
  const std::filesystem::path marker = run.dir / L"finalize.request";
  {
    std::ofstream out(marker, std::ios::binary | std::ios::trunc);
    out << "requested=mcp-vm_finalize\n";
  }
  std::error_code ec;
  if (!std::filesystem::exists(marker, ec)) {
    return std::string("{\"ok\":false,\"error\":") +
           JsonQuote("could not write " + PathToUtf8(marker)) + "}";
  }
  const bool wait = ArgBool(args, "wait", false);
  bool finalized = false;
  if (wait) {
    const int waitSec = ArgInt(args, "wait_sec", 120);
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(waitSec > 0 ? waitSec : 120);
    while (std::chrono::steady_clock::now() < deadline) {
      if (std::filesystem::exists(run.reportJson, ec)) {
        finalized = true;
        break;
      }
      Sleep(250);
    }
  }
  std::ostringstream o;
  o << "{\"ok\":true,\"runDir\":" << JsonQuote(PathToUtf8(run.dir))
    << ",\"finalizeRequested\":true"
    << ",\"reportJson\":" << (std::filesystem::exists(run.reportJson, ec) ? "true" : "false")
    << ",\"waited\":" << (wait ? "true" : "false")
    << ",\"note\":\"The run loop ends through the normal report path; poll "
       "vm_report/vm_status for report.json. Use vm_stop only as a lossy "
       "emergency stop.\"}";
  return o.str();
}

std::string ToolVmStop(const antimal::AppConfig &cfg, const JsonValue &args) {
  const bool force = ArgBool(args, "force", false);
  const antimal::LiveFrame probe = antimal::ReadLiveFrame(antimal::kLiveFrameShmName);
  if (!probe.present && !force) {
    return R"({"ok":true,"stopped":0,"note":"no live VM detected; pass force=true to kill stray HostCli processes anyway"})";
  }
  const std::vector<antimal::ProcessEntry> procs =
      antimal::FindProcessesByName(L"AntiMal.HostCli.exe");
  std::ostringstream o;
  o << "{\"ok\":true,\"stopped\":0,\"pids\":[";
  int stopped = 0;
  for (size_t i = 0; i < procs.size(); ++i) {
    // Only the VM host (`detonate`) is a kill target by default -- a
    // concurrent `scan` in another HostCli must survive. An unreadable
    // command line is treated as "not the VM host" (use force=true).
    const bool isVmHost =
        procs[i].commandLine.find(L"detonate") != std::wstring::npos;
    if (!force && !isVmHost) {
      continue;
    }
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, procs[i].pid);
    if (!h) {
      continue;
    }
    if (i) {
      o << ",";
    }
    o << procs[i].pid;
    TerminateProcess(h, 1);
    CloseHandle(h);
    ++stopped;
  }
  o << "],\"stopped\":" << stopped
    << ",\"note\":\"Default only targets the detonate VM host; force=true "
       "kills every AntiMal.HostCli.exe.\"}";
  return o.str();
}

// ---- Tool schema / dispatch -------------------------------------------------

const char *kToolsJson = R"JSON({"tools":[
{"name":"vm_status","description":"State of the live analysis VM: is the framebuffer present/advancing, resolution, fps, newest run directory, whether events.jsonl/report.json exist, and the host process. Call this first; on ok=false nothing else can work.","inputSchema":{"type":"object","properties":{}}},
{"name":"vm_screenshot","description":"Capture the live guest screen to a PNG and return its path. ALWAYS look at the returned image (read the file) before and after acting: verify a desktop is actually rendering, and never describe what you did not see. blank=true means no desktop is painted yet.","inputSchema":{"type":"object","properties":{"out":{"type":"string","description":"Optional output path; defaults under <workspace>/_mcp/."}}}},
{"name":"vm_click","description":"Move the guest pointer to (x, y) with the closed-loop tracker and click there. Coordinates are guest-screen pixels, origin top-left. The result carries the measured cursor position and remaining pixel error; if ok=false the click did NOT land. Take the after screenshot and confirm the UI changed.","inputSchema":{"type":"object","properties":{"x":{"type":"integer"},"y":{"type":"integer"},"button":{"type":"string","enum":["left","right","middle"],"default":"left"},"clicks":{"type":"integer","default":1},"screenshot":{"type":"boolean","default":true}},"required":["x","y"]}},
{"name":"vm_move","description":"Move the guest pointer to (x, y) without clicking. Returns the measured cursor position/error. Use vm_screenshot to see where it ended up.","inputSchema":{"type":"object","properties":{"x":{"type":"integer"},"y":{"type":"integer"},"screenshot":{"type":"boolean","default":true}},"required":["x","y"]}},
{"name":"vm_drag","description":"Press at (x1, y1), drag to (x2, y2), release -- for sliders, window moves, selection. Verify with the returned screenshot.","inputSchema":{"type":"object","properties":{"x1":{"type":"integer"},"y1":{"type":"integer"},"x2":{"type":"integer"},"y2":{"type":"integer"},"button":{"type":"string","enum":["left","right","middle"],"default":"left"},"screenshot":{"type":"boolean","default":true}},"required":["x1","y1","x2","y2"]}},
{"name":"vm_type","description":"Type text into the FOCUSED guest control (click the field first). The result screenshots the field afterwards so you can confirm the text landed.","inputSchema":{"type":"object","properties":{"text":{"type":"string"},"interval_ms":{"type":"integer","default":30},"screenshot":{"type":"boolean","default":true}},"required":["text"]}},
{"name":"vm_key","description":"Tap one key by name (enter, tab, esc, space, backspace, delete, up/down/left/right, home, end, f1..f12) or a single character.","inputSchema":{"type":"object","properties":{"key":{"type":"string"},"screenshot":{"type":"boolean","default":true}},"required":["key"]}},
{"name":"vm_chord","description":"Tap a key chord like 'ctrl+alt+del', 'alt+f4', 'win+r', 'ctrl+shift+esc'.","inputSchema":{"type":"object","properties":{"chord":{"type":"string"},"screenshot":{"type":"boolean","default":true}},"required":["chord"]}},
{"name":"vm_events","description":"Tail the live telemetry journal (events.jsonl) of the newest or a given run. This is raw observed behavior (process/file/registry/network/image-load events). Use since_line/nextLine to poll incrementally. Cite concrete events as evidence; do not infer intent from a single line.","inputSchema":{"type":"object","properties":{"run":{"type":"string","description":"Run id/dir or absolute path; default = newest run."},"since_line":{"type":"integer","default":0},"limit":{"type":"integer","default":200},"filter":{"type":"string","description":"Optional substring; the line must contain it."}}}},
{"name":"vm_processes","description":"Summarize each observed process (pid, parent, image, full path, command line, user, integrity, last action, ATT&CK tag) from the live journal. Use it to answer 'what actually ran' with names and paths you can cite.","inputSchema":{"type":"object","properties":{"run":{"type":"string"}}}},
{"name":"vm_report","description":"Read the run's report.json verdict fields AND the verdict rationale (only exists once the run completes). A verdict without rationale/evidence is not a result: cross-check it against vm_processes/vm_events and the screenshots you took.","inputSchema":{"type":"object","properties":{"run":{"type":"string"}}}},
{"name":"vm_boot","description":"Start the interactive live VM exactly like the GUI's Boot VM (live): seed snapshot when present, live framebuffer + input channels, and (default view=true) the watchable vmview window so the operator SEES every action. Non-executing by default; allow_execution=true arms the sample-execution gate for an explicit detonation. Booting to a usable desktop can take minutes -- poll vm_status and vm_screenshot rather than assuming.","inputSchema":{"type":"object","properties":{"view":{"type":"boolean","default":true},"sample":{"type":"string","description":"Sample path; defaults to AntiMal.Tests.exe (benign)."},"timeout_sec":{"type":"integer","default":0,"description":"0 = until stopped (call vm_finalize to end); >0 = optional automatic analysis budget in seconds."},"allow_execution":{"type":"boolean","default":false}}}},
{"name":"vm_view","description":"Open the watchable live VM window (vmview) so the operator can see the guest screen while you drive it.","inputSchema":{"type":"object","properties":{}}},
{"name":"vm_finalize","description":"Gracefully END the live session and finalize the evidence: the run exits through the normal report-writing path, so report.json is written with the verdict/rationale. This is the normal stop. Optional wait=true polls until report.json appears.","inputSchema":{"type":"object","properties":{"run":{"type":"string","description":"Run id/dir; default = newest live run."},"wait":{"type":"boolean","default":false},"wait_sec":{"type":"integer","default":120}}}},
{"name":"vm_stop","description":"EMERGENCY stop: kills the HostCli VM host process. This can lose the finalized report (recover partial evidence with rebuild-report). Prefer vm_finalize for a normal end. Only acts when a live VM is present unless force=true.","inputSchema":{"type":"object","properties":{"force":{"type":"boolean","default":false}}}}
]})JSON";

std::string DispatchTool(const antimal::AppConfig &cfg, const std::string &name,
                         const JsonValue &args, bool *isError) {
  *isError = false;
  if (name == "vm_status") return ToolVmStatus(cfg);
  if (name == "vm_screenshot") return ToolVmScreenshot(cfg, args);
  if (name == "vm_click") return ToolVmClick(cfg, args);
  if (name == "vm_move") return ToolVmMove(cfg, args);
  if (name == "vm_drag") return ToolVmDrag(cfg, args);
  if (name == "vm_type") return ToolVmType(cfg, args);
  if (name == "vm_key") return ToolVmKey(cfg, args);
  if (name == "vm_chord") return ToolVmChord(cfg, args);
  if (name == "vm_events") return ToolVmEvents(cfg, args);
  if (name == "vm_processes") return ToolVmProcesses(cfg, args);
  if (name == "vm_report") return ToolVmReport(cfg, args);
  if (name == "vm_boot") return ToolVmBoot(cfg, args);
  if (name == "vm_view") return ToolVmView(cfg, args);
  if (name == "vm_finalize") return ToolVmFinalize(cfg, args);
  if (name == "vm_stop") return ToolVmStop(cfg, args);
  *isError = true;
  return std::string("{\"ok\":false,\"error\":") +
         JsonQuote("unknown tool: " + name) + "}";
}

} // namespace

#include <fstream>

int main() {
  _setmode(_fileno(stdin), _O_BINARY);
  _setmode(_fileno(stdout), _O_BINARY);

  const char *tracePath = std::getenv("ANTIMAL_MCP_TRACE");
  auto trace = [tracePath](const std::string &m) {
    if (tracePath == nullptr) {
      return;
    }
    std::ofstream f(tracePath, std::ios::app);
    if (f) {
      f << m << "\n";
      f.flush();
    }
  };
  trace("spawned");

  const antimal::AppConfig cfg =
      antimal::LoadConfig(antimal::DefaultConfigPath());
  if (std::getenv("ANTIMAL_MCP_LOG") != nullptr) {
    Log("workspace root: " + antimal::PathToUtf8(cfg.workspaceRoot));
  }

  std::string line;
  while (std::getline(std::cin, line)) {
    trace("in: " + line);
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    if (line.empty()) {
      continue;
    }
    const auto parsed = antimal::ParseJson(line);
    if (!parsed) {
      Log("dropped a non-JSON stdin line");
      trace("dropped non-JSON line");
      continue;
    }
    const JsonValue &msg = *parsed;
    const std::string method = msg.At("method").AsString();
    trace("method: " + method);
    const bool hasId = msg.Has("id");
    const JsonValue &id = msg.At("id");

    if (method == "initialize") {
      // Echo the client's protocol revision when it offers one; the tool
      // surface is version-agnostic.
      const std::string requested = msg.At("params").At("protocolVersion").AsString();
      const std::string version =
          requested.empty() ? "2024-11-05" : requested;
      SendResult(id,
                 std::string("{\"protocolVersion\":") + JsonQuote(version) +
                     ",\"capabilities\":{\"tools\":{\"listChanged\":false}}"
                     ",\"serverInfo\":{\"name\":\"antimal\",\"version\":" +
                     JsonQuote(antimal::kVersionString) + "}}");
    } else if (method == "notifications/initialized" ||
               method.rfind("notifications/", 0) == 0) {
      // Notifications carry no reply; nothing to do for any of them.
    } else if (method == "ping") {
      if (hasId) {
        SendResult(id, "{}");
      }
    } else if (method == "tools/list") {
      if (hasId) {
        SendResult(id, kToolsJson);
      }
    } else if (method == "tools/call") {
      const std::string name = msg.At("params").At("name").AsString();
      const JsonValue &args = msg.At("params").At("arguments");
      bool isError = false;
      const std::string payload = DispatchTool(cfg, name, args, &isError);
      if (hasId) {
        SendResult(id, TextResult(payload, isError));
      }
    } else if (method == "resources/list") {
      // AntiMal exposes tools only. Clients (opencode included) still ask for
      // resources/prompts unconditionally, and a JSON-RPC ERROR here makes them
      // treat the whole server as broken ("Failed to get tools"). Answer with
      // valid empty lists instead.
      if (hasId) {
        SendResult(id, "{\"resources\":[]}");
      }
    } else if (method == "resources/templates/list") {
      if (hasId) {
        SendResult(id, "{\"resourceTemplates\":[]}");
      }
    } else if (method == "prompts/list") {
      if (hasId) {
        SendResult(id, "{\"prompts\":[]}");
      }
    } else if (method == "logging/setLevel" || method == "completion/complete" ||
               method == "resources/subscribe" ||
               method == "resources/unsubscribe") {
      if (hasId) {
        SendResult(id, "{}");
      }
    } else if (hasId) {
      SendError(id, -32601, "method not found: " + method);
    }
  }
  return 0;
}
