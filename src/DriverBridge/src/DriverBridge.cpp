#include "antimal/DriverBridge.h"

#include <Windows.h>

namespace antimal {

bool DriverBridge::ConnectToAlreadyLoadedHelper(const std::wstring &endpointName) {
  connected_ = false;
  lastError_.clear();

  if (endpointName.empty()) {
    lastError_ = "Driver bridge endpoint was empty.";
    return false;
  }

  lastError_ =
      "Dev-only driver bridge is intentionally passive. Load and expose a documented helper "
      "endpoint separately, then replace this adapter with the approved local protocol.";
  return false;
}

bool DriverBridge::IsConnected() const { return connected_; }

std::string DriverBridge::LastError() const { return lastError_; }

} // namespace antimal
