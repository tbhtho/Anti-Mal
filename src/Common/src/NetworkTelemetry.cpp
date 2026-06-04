#include "antimal/NetworkTelemetry.h"

#include "antimal/FileUtil.h"  // UtcNowIso8601

namespace antimal {

std::string TcpConnectionKey(const TcpConnection &c) {
  return std::to_string(c.pid) + "|" + c.localAddress + ":" +
         std::to_string(c.localPort) + "|" + c.remoteAddress + ":" +
         std::to_string(c.remotePort);
}

namespace {

EventRecord MakeNetEvent(const TcpConnection &c, std::string action) {
  EventRecord ev;
  ev.timestampUtc = UtcNowIso8601();
  ev.source = "GuestAgent";
  ev.category = "network";
  ev.action = std::move(action);
  ev.processId = c.pid;
  ev.target = c.remoteAddress + ":" + std::to_string(c.remotePort);
  ev.details["localAddress"] = c.localAddress;
  ev.details["localPort"] = std::to_string(c.localPort);
  ev.details["remotePort"] = std::to_string(c.remotePort);
  ev.details["state"] = c.state;
  return ev;
}

}  // namespace

std::vector<EventRecord> DiffTcpConnections(const TcpSnapshot &prev,
                                            const TcpSnapshot &cur,
                                            bool emitBaseline, size_t baselineCap,
                                            size_t deltaCap) {
  std::vector<EventRecord> out;
  if (emitBaseline) {
    size_t n = 0;
    for (const auto &entry : cur) {
      if (n++ >= baselineCap) break;
      out.push_back(MakeNetEvent(entry.second, "network.connection"));
    }
    return out;
  }
  size_t started = 0;
  for (const auto &entry : cur) {
    if (prev.find(entry.first) == prev.end()) {
      if (started++ >= deltaCap) continue;
      out.push_back(MakeNetEvent(entry.second, "network.connect"));
    }
  }
  for (const auto &entry : prev) {
    if (cur.find(entry.first) == cur.end()) {
      out.push_back(MakeNetEvent(entry.second, "network.close"));
    }
  }
  return out;
}

}  // namespace antimal
