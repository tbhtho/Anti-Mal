#pragma once

// The single C++<->JS seam for the WebView2 UI. The web UI posts JSON command
// envelopes { "cmd": <string>, "reqId": <int>, "args": <object> }; the router
// validates, dispatches to a registered handler, and returns a JSON reply
// { "reqId": <int>, "ok": <bool>, "result": <json> | "error": <string> }.
//
// Pure C++ with no WebView2 / Win32 dependency so it can be unit-tested in
// AntiMal.Tests and reused by the App's WebViewHost transport.

#include "antimal/JsonValue.h"

#include <functional>
#include <string>
#include <unordered_map>

namespace antimal {

// A handler receives the parsed `args` value and returns the *result* as a JSON
// string (e.g. R"({"version":"1"})" or "null"). Throwing is allowed — the
// router contains the exception and reports ok=false, so a buggy handler can
// never escape onto the UI thread.
using BridgeHandler = std::function<std::string(const JsonValue &args)>;

class BridgeRouter {
public:
  void Register(const std::string &cmd, BridgeHandler handler);

  // Parses `message`, dispatches, and returns the reply JSON. Never throws.
  std::string Handle(const std::string &message) noexcept;

  bool HasHandler(const std::string &cmd) const {
    return handlers_.count(cmd) != 0;
  }

private:
  std::unordered_map<std::string, BridgeHandler> handlers_;
};

} // namespace antimal
