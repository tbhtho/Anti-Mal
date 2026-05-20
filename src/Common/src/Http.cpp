#include "antimal/Http.h"

#include "antimal/FileUtil.h"

#include <Windows.h>
#include <winhttp.h>

#include <sstream>

namespace antimal {
namespace {

struct WinHttpHandle {
  HINTERNET h = nullptr;
  ~WinHttpHandle() {
    if (h) WinHttpCloseHandle(h);
  }
  operator HINTERNET() const noexcept { return h; }
};

struct ParsedUrl {
  std::wstring host;
  std::wstring path;
  INTERNET_PORT port = INTERNET_DEFAULT_HTTPS_PORT;
  bool https = true;
};

bool ParseUrl(const std::string &url, ParsedUrl &out, std::string &error) {
  const auto wide = Utf8ToWide(url);
  URL_COMPONENTSW c{};
  c.dwStructSize = sizeof(c);
  c.dwHostNameLength = static_cast<DWORD>(-1);
  c.dwUrlPathLength = static_cast<DWORD>(-1);
  c.dwSchemeLength = static_cast<DWORD>(-1);
  c.dwExtraInfoLength = static_cast<DWORD>(-1);
  if (!WinHttpCrackUrl(wide.c_str(), 0, 0, &c)) {
    error = "WinHttpCrackUrl failed";
    return false;
  }
  out.host.assign(c.lpszHostName, c.dwHostNameLength);
  // Combine path + extra (query string).
  out.path.assign(c.lpszUrlPath, c.dwUrlPathLength);
  if (c.lpszExtraInfo && c.dwExtraInfoLength > 0) {
    out.path.append(c.lpszExtraInfo, c.dwExtraInfoLength);
  }
  if (out.path.empty()) out.path = L"/";
  out.port = c.nPort;
  out.https = (c.nScheme == INTERNET_SCHEME_HTTPS);
  return true;
}

std::string HeadersToString(const std::map<std::string, std::string> &headers,
                            const std::string &contentType) {
  std::string out;
  bool hasContentType = false;
  for (const auto &[k, v] : headers) {
    if (ToLowerAscii(k) == "content-type") hasContentType = true;
    out.append(k);
    out.append(": ");
    out.append(v);
    out.append("\r\n");
  }
  if (!hasContentType && !contentType.empty()) {
    out.append("Content-Type: ");
    out.append(contentType);
    out.append("\r\n");
  }
  return out;
}

std::map<std::string, std::string> ParseResponseHeaders(const std::wstring &raw) {
  std::map<std::string, std::string> out;
  std::wstringstream stream(raw);
  std::wstring line;
  while (std::getline(stream, line)) {
    if (!line.empty() && line.back() == L'\r') line.pop_back();
    const auto colon = line.find(L':');
    if (colon == std::wstring::npos) continue;
    auto key = WideToUtf8(line.substr(0, colon));
    auto value = WideToUtf8(line.substr(colon + 1));
    out[ToLowerAscii(Trim(key))] = Trim(value);
  }
  return out;
}

} // namespace

std::string UrlEncode(std::string_view value) {
  std::ostringstream out;
  out.fill('0');
  out << std::hex;
  for (unsigned char c : value) {
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      out << static_cast<char>(c);
    } else {
      out << '%' << std::uppercase;
      out.width(2);
      out << static_cast<int>(c);
      out << std::nouppercase;
    }
  }
  return out.str();
}

HttpResponse HttpRequestSync(const HttpRequest &request) {
  HttpResponse response;

  ParsedUrl url;
  if (!ParseUrl(request.url, url, response.error)) {
    return response;
  }

  WinHttpHandle session;
  session.h = WinHttpOpen(L"AntiMal/1.0",
                          WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                          WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!session.h) {
    response.error = "WinHttpOpen failed";
    return response;
  }
  const DWORD timeoutMs = static_cast<DWORD>(request.timeout.count());
  WinHttpSetTimeouts(session.h, static_cast<int>(timeoutMs),
                     static_cast<int>(timeoutMs), static_cast<int>(timeoutMs),
                     static_cast<int>(timeoutMs));

  WinHttpHandle conn;
  conn.h = WinHttpConnect(session.h, url.host.c_str(), url.port, 0);
  if (!conn.h) {
    response.error = "WinHttpConnect failed";
    return response;
  }

  DWORD flags = url.https ? WINHTTP_FLAG_SECURE : 0;
  WinHttpHandle req;
  req.h = WinHttpOpenRequest(conn.h, Utf8ToWide(request.method).c_str(),
                             url.path.c_str(), nullptr,
                             WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                             flags);
  if (!req.h) {
    response.error = "WinHttpOpenRequest failed";
    return response;
  }

  const std::string contentType = request.contentType.empty()
                                      ? "application/x-www-form-urlencoded"
                                      : request.contentType;
  const std::string headersUtf8 =
      HeadersToString(request.headers, request.body.empty() ? "" : contentType);
  const std::wstring headersWide = Utf8ToWide(headersUtf8);

  const void *bodyPtr =
      request.body.empty() ? WINHTTP_NO_REQUEST_DATA
                           : static_cast<const void *>(request.body.data());
  const DWORD bodyLen = static_cast<DWORD>(request.body.size());

  if (!WinHttpSendRequest(req.h,
                          headersWide.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS
                                              : headersWide.c_str(),
                          static_cast<DWORD>(-1),
                          const_cast<void *>(bodyPtr), bodyLen, bodyLen, 0)) {
    response.error = "WinHttpSendRequest failed";
    return response;
  }
  if (!WinHttpReceiveResponse(req.h, nullptr)) {
    response.error = "WinHttpReceiveResponse failed";
    return response;
  }

  DWORD status = 0;
  DWORD statusSize = sizeof(status);
  if (!WinHttpQueryHeaders(req.h,
                           WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                           WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize,
                           WINHTTP_NO_HEADER_INDEX)) {
    response.error = "WinHttpQueryHeaders(status) failed";
    return response;
  }
  response.status = static_cast<int>(status);

  // Pull full response headers blob for diagnostics.
  DWORD headerLen = 0;
  WinHttpQueryHeaders(req.h, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                      WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &headerLen,
                      WINHTTP_NO_HEADER_INDEX);
  if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && headerLen > 0) {
    std::wstring buf(headerLen / sizeof(wchar_t), L'\0');
    if (WinHttpQueryHeaders(req.h, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                            WINHTTP_HEADER_NAME_BY_INDEX, buf.data(), &headerLen,
                            WINHTTP_NO_HEADER_INDEX)) {
      response.headers = ParseResponseHeaders(buf);
    }
  }

  // Drain body.
  for (;;) {
    DWORD available = 0;
    if (!WinHttpQueryDataAvailable(req.h, &available)) break;
    if (available == 0) break;
    std::string chunk(available, '\0');
    DWORD read = 0;
    if (!WinHttpReadData(req.h, chunk.data(), available, &read)) break;
    chunk.resize(read);
    response.body.append(chunk);
  }

  response.ok = true;
  return response;
}

} // namespace antimal
