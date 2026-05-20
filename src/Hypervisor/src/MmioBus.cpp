#include "antimal/hv/MmioBus.h"

namespace antimal::hv {

void MmioBus::Attach(IMmioDevice *device) {
  if (device) {
    devices_.push_back(device);
  }
}

IMmioDevice *MmioBus::Find(uint64_t gpa) const {
  for (auto *device : devices_) {
    if (device && gpa >= device->MmioBase() && gpa <= device->MmioLast()) {
      return device;
    }
  }
  return nullptr;
}

bool MmioBus::Read(uint64_t gpa, uint8_t accessSize, uint64_t *outValue) {
  auto *device = Find(gpa);
  if (!device) {
    if (outValue) {
      *outValue = 0xFFFFFFFFFFFFFFFFull;
    }
    return false;
  }
  uint64_t value = 0;
  const bool ok = device->OnRead(gpa, accessSize, &value);
  if (outValue) {
    *outValue = ok ? value : 0xFFFFFFFFFFFFFFFFull;
  }
  return ok;
}

bool MmioBus::Write(uint64_t gpa, uint8_t accessSize, uint64_t value) {
  auto *device = Find(gpa);
  if (!device) {
    return false;
  }
  return device->OnWrite(gpa, accessSize, value);
}

} // namespace antimal::hv
