#include "antimal/BridgeRouter.h"

#include "antimal/Json.h" // JsonQuote

#include <exception>
#include <string>

namespace antimal {

void BridgeRouter::Register(const std::string &cmd, BridgeHandler handler) {
  handlers_[cmd] = std::move(handler);
}

std::string BridgeRouter::Handle(const std::string &message) noexcept {
  try {
    const auto parsed = ParseJson(message);
    if (!parsed || !parsed->IsObject()) {
      return R"({"reqId":0,"ok":false,"error":"bad envelope"})";
    }

    const std::string reqId = std::to_string(parsed->At("reqId").AsInt64());

    const JsonValue &cmdVal = parsed->At("cmd");
    if (!cmdVal.IsString()) {
      return "{\"reqId\":" + reqId + ",\"ok\":false,\"error\":\"missing cmd\"}";
    }
    const std::string &cmd = cmdVal.AsString();

    const auto it = handlers_.find(cmd);
    if (it == handlers_.end()) {
      return "{\"reqId\":" + reqId + ",\"ok\":false,\"error\":" +
             JsonQuote("unknown command: " + cmd) + "}";
    }

    const JsonValue &args = parsed->At("args");
    try {
      std::string result = it->second(args);
      if (result.empty()) {
        result = "null";
      }
      return "{\"reqId\":" + reqId + ",\"ok\":true,\"result\":" + result + "}";
    } catch (const std::exception &e) {
      return "{\"reqId\":" + reqId + ",\"ok\":false,\"error\":" +
             JsonQuote(std::string("handler error: ") + e.what()) + "}";
    } catch (...) {
      return "{\"reqId\":" + reqId +
             ",\"ok\":false,\"error\":\"handler failed\"}";
    }
  } catch (...) {
    return R"({"reqId":0,"ok":false,"error":"internal error"})";
  }
}

} // namespace antimal
