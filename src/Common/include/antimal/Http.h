#pragma once

// Minimal WinHTTP client. Just enough HTTPS GET/POST to call threat-intel
// APIs (MalwareBazaar, VirusTotal). Not a general-purpose HTTP library.
//
// Consumers link winhttp.lib. Failures are non-throwing — the result struct
// carries the diagnostic so callers don't have to wrap in try/catch.

#include <chrono>
#include <map>
#include <string>
#include <vector>

namespace antimal {

struct HttpResponse {
  bool ok = false;          // Network call completed (status code is in `status`).
  int status = 0;           // HTTP status code (0 when transport failed).
  std::string body;         // Response body.
  std::string error;        // Diagnostic when ok == false.
  std::map<std::string, std::string> headers;
};

struct HttpRequest {
  std::string url;                  // https://example.com/path?query
  std::string method = "GET";       // "GET" | "POST"
  std::map<std::string, std::string> headers;
  std::string body;                 // Set for POST/PUT.
  std::string contentType;          // Convenience; defaults to "application/x-www-form-urlencoded" when body set.
  std::chrono::milliseconds timeout{30000};
};

HttpResponse HttpRequestSync(const HttpRequest &request);

// URL-encodes a single value (RFC 3986 unreserved set).
std::string UrlEncode(std::string_view value);

} // namespace antimal
