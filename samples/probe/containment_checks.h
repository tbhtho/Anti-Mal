#pragma once
// Only used by the benign package fixture. Targets are synthetic test data.
#include <iphlpapi.h>
#include <fstream>
#include <filesystem>
#include <vector>

inline void RunContainmentChecks() {
  wchar_t module[32768]{};
  GetModuleFileNameW(nullptr, module, 32768);
  const auto config = std::filesystem::path(module).parent_path() /
                      L"resources" / L"containment-targets.txt";
  std::ifstream input(config);
  if (!input) return; // Ordinary GUI fixture has no containment targets.
  std::string canary, address, marker;
  std::getline(input, canary); std::getline(input, address); std::getline(input, marker);
  for (auto *s : {&canary, &address, &marker})
    if (!s->empty() && s->back() == '\r') s->pop_back();
  std::ofstream out(L"C:\\Users\\Public\\antimal-containment-results.txt");
  out << "package_sibling=" << (marker == "ANTIMAL_SYNTHETIC_PACKAGE_V1") << "\n";
  if (canary.rfind("C:\\AntiMalRuns\\_containment\\", 0) != 0 ||
      marker != "ANTIMAL_SYNTHETIC_PACKAGE_V1") {
    out << "configuration=invalid\n"; return;
  }
  HANDLE file = CreateFileA(canary.c_str(), GENERIC_READ, FILE_SHARE_READ,
      nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  DWORD readError = file == INVALID_HANDLE_VALUE ? GetLastError() : 0;
  out << "host_canary_read_open=" << (file != INVALID_HANDLE_VALUE)
      << " error=" << readError << "\n";
  if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
  // OPEN_EXISTING + no WriteFile: even an unexpected success cannot alter it.
  file = CreateFileA(canary.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
      nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  out << "host_canary_write_open=" << (file != INVALID_HANDLE_VALUE)
      << " error=" << (file == INVALID_HANDLE_VALUE ? GetLastError() : 0) << "\n";
  if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
  unsigned remoteDrives = 0;
  DWORD drives = GetLogicalDrives();
  for (unsigned i = 0; i < 26; ++i) if (drives & (1u << i)) {
    char root[] = "A:\\"; root[0] = static_cast<char>('A' + i);
    if (GetDriveTypeA(root) == DRIVE_REMOTE) ++remoteDrives;
  }
  out << "mapped_remote_drives=" << remoteDrives << "\n";
  ULONG size = 16384;
  std::vector<unsigned char> storage(size);
  ULONG result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES,
      nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES *>(storage.data()), &size);
  if (result == ERROR_BUFFER_OVERFLOW && size <= 1024 * 1024) {
    storage.resize(size);
    result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES,
        nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES *>(storage.data()), &size);
  }
  unsigned nonLoopback = 0;
  if (result == NO_ERROR) {
    for (auto *adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(storage.data());
         adapter; adapter = adapter->Next)
      if (adapter->IfType != IF_TYPE_SOFTWARE_LOOPBACK) ++nonLoopback;
  }
  out << "adapter_query_error=" << result << " nonloopback_adapters=" << nonLoopback << "\n";
  WSADATA data{};
  int networkError = WSAStartup(MAKEWORD(2, 2), &data);
  bool connected = false;
  if (!networkError) {
    SOCKET socketHandle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socketHandle != INVALID_SOCKET) {
      u_long nonblocking = 1;
      ioctlsocket(socketHandle, FIONBIO, &nonblocking);
      sockaddr_in endpoint{}; endpoint.sin_family = AF_INET; endpoint.sin_port = htons(49199);
      if (InetPtonA(AF_INET, address.c_str(), &endpoint.sin_addr) != 1) networkError = WSAEINVAL;
      else {
        connected = connect(socketHandle, reinterpret_cast<sockaddr *>(&endpoint), sizeof(endpoint)) == 0;
        networkError = connected ? 0 : WSAGetLastError();
        if (networkError == WSAEWOULDBLOCK) {
          fd_set writable, errors; FD_ZERO(&writable); FD_ZERO(&errors);
          FD_SET(socketHandle, &writable); FD_SET(socketHandle, &errors);
          timeval timeout{2, 0};
          int ready = select(0, nullptr, &writable, &errors, &timeout);
          if (ready > 0) {
            int length = sizeof(networkError);
            getsockopt(socketHandle, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&networkError), &length);
            connected = networkError == 0;
          } else networkError = ready == 0 ? WSAETIMEDOUT : WSAGetLastError();
        }
      }
      closesocket(socketHandle);
    } else networkError = WSAGetLastError();
    WSACleanup();
  }
  out << "host_tcp_connected=" << connected << " error=" << networkError << "\n";
  out << "complete=1\n";
}
