#pragma once

#include <string>

namespace antimal {

class DriverBridge {
public:
  bool ConnectToAlreadyLoadedHelper(const std::wstring &endpointName);
  bool IsConnected() const;
  std::string LastError() const;

private:
  bool connected_ = false;
  std::string lastError_;
};

} // namespace antimal
