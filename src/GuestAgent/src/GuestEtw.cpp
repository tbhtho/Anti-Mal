#include "GuestEtw.h"
#include "antimal/FileUtil.h"
#include "antimal/BoundedTelemetryQueue.h"
#include <Windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <atomic>
#include <cstring>
#include <climits>
#include <charconv>
#include <deque>
#include <map>
#include <mutex>
#include <thread>

namespace {
constexpr wchar_t kSession[] = L"AntiMal-Guest-Behavior";
std::string MetadataString(const std::vector<BYTE>& data, ULONG offset) {
  if (!offset || offset >= data.size() || offset % sizeof(wchar_t)) return {};
  const auto* p = reinterpret_cast<const wchar_t*>(data.data() + offset);
  const size_t limit = (data.size() - offset) / sizeof(wchar_t);
  size_t n = 0;
  while (n < limit && n < 2048 && p[n]) ++n;
  return antimal::WideToUtf8(std::wstring(p, n));
}
std::string Timestamp(LONGLONG value) {
  ULARGE_INTEGER time{}; time.QuadPart = value;
  FILETIME ft{time.LowPart, time.HighPart}; SYSTEMTIME st{};
  if (!FileTimeToSystemTime(&ft, &st)) return antimal::UtcNowIso8601();
  char out[40]{};
  sprintf_s(out, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", st.wYear,
      st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
  return out;
}
bool SensitivePath(const std::string& path) {
  const auto lower = antimal::ToLowerAscii(path);
  for (const auto* marker : {"\\antimal-probe-sensitive\\", "\\login data",
      "\\cookies", "\\local state", "\\credentials\\", "\\protect\\",
      "\\.ssh\\", "\\wallet", "\\leveldb\\"})
    if (lower.find(marker) != std::string::npos) return true;
  return false;
}
}

struct GuestEtw::Impl {
  struct Provider {
    const wchar_t* name;
    const char* sensor;
    const char* category;
    ULONGLONG keywords;
    GUID guid{};
    ULONG status = ERROR_NOT_FOUND;
    std::atomic_uint64_t seen{0}, dropped{0}, decodeErrors{0};
  } providers[6] = {
    {L"Microsoft-Windows-DNS-Client", "etw_dns", "network", ~0ull},
    {L"Microsoft-Windows-WinHttp", "etw_winhttp", "network", ~0ull},
    {L"Microsoft-Windows-WinINet", "etw_wininet", "network", ~0ull},
    {L"Microsoft-Windows-Kernel-Process", "etw_process", "process", 0x10},
    {L"Microsoft-Windows-Kernel-File", "etw_sensitive_file", "file", 0x190},
    {L"Microsoft-Windows-Winsock-AFD", "etw_socket", "network", ~0ull}
  };
  TRACEHANDLE session = 0, consumer = INVALID_PROCESSTRACE_HANDLE;
  std::vector<BYTE> properties;
  std::thread thread;
  antimal::BoundedTelemetryQueue<antimal::EventRecord> queue;
  std::map<std::string, std::string> sensitiveObjects; // consumer thread only
  std::map<unsigned, std::vector<BYTE>> fileSchemas; // manifest file provider only
  std::atomic<ULONG> processStatus{ERROR_SUCCESS};
  ULONG startStatus = ERROR_SUCCESS;
  uint64_t osLost = 0;
  EVENT_TRACE_PROPERTIES* Props() {
    return reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties.data());
  }
  Impl() {
    properties.resize(sizeof(EVENT_TRACE_PROPERTIES) + sizeof(kSession));
    auto* p = Props();
    p->Wnode.BufferSize = static_cast<ULONG>(properties.size());
    p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    p->Wnode.ClientContext = 1; // QPC; ProcessTrace converts to FILETIME
    p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    p->BufferSize = 64; p->MinimumBuffers = 8; p->MaximumBuffers = 64;
    p->FlushTimer = 1;
    startStatus = StartTraceW(&session, kSession, p);
    if (startStatus != ERROR_SUCCESS) { session = 0; return; }
    EVENT_TRACE_LOGFILEW log{};
    log.LoggerName = const_cast<LPWSTR>(kSession);
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = Callback; log.Context = this;
    consumer = OpenTraceW(&log);
    if (consumer == INVALID_PROCESSTRACE_HANDLE) { startStatus = GetLastError(); return; }
    ULONG bytes = 0;
    if (TdhEnumerateProviders(nullptr, &bytes) == ERROR_INSUFFICIENT_BUFFER && bytes <= 4*1024*1024) {
      std::vector<BYTE> buffer(bytes);
      auto* list = reinterpret_cast<PROVIDER_ENUMERATION_INFO*>(buffer.data());
      if (TdhEnumerateProviders(list, &bytes) == ERROR_SUCCESS) {
        const size_t available = (buffer.size() - offsetof(PROVIDER_ENUMERATION_INFO, TraceProviderInfoArray)) / sizeof(TRACE_PROVIDER_INFO);
        for (ULONG i = 0; i < list->NumberOfProviders && i < available; ++i) {
          const auto& found = list->TraceProviderInfoArray[i];
          const auto name = MetadataString(buffer, found.ProviderNameOffset);
          for (auto& provider : providers) if (name == antimal::WideToUtf8(provider.name)) {
            provider.guid = found.ProviderGuid;
            provider.status = EnableTraceEx2(session, &provider.guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE,
                provider.keywords, 0, 1000, nullptr);
          }
        }
      }
    }
    thread = std::thread([this] { processStatus = ProcessTrace(&consumer, 1, nullptr, nullptr); });
  }
  ~Impl() {
    Stop();
  }
  void Stop() {
    if (session) {
      ControlTraceW(session, kSession, Props(), EVENT_TRACE_CONTROL_STOP);
      osLost = static_cast<uint64_t>(Props()->EventsLost) + Props()->RealTimeBuffersLost;
      session = 0;
    }
    if (consumer != INVALID_PROCESSTRACE_HANDLE) CloseTrace(consumer);
    if (thread.joinable()) thread.join();
    consumer = INVALID_PROCESSTRACE_HANDLE;
  }
  static void WINAPI Callback(EVENT_RECORD* record) noexcept {
    auto* self = static_cast<Impl*>(record->UserContext);
    if (!self) return;
    try { self->Receive(record); } catch (...) {
      for (auto& p : self->providers)
        if (IsEqualGUID(p.guid, record->EventHeader.ProviderId)) ++p.decodeErrors;
    }
  }
  void Receive(EVENT_RECORD* record) {
    Provider* provider = nullptr;
    for (auto& p : providers) if (IsEqualGUID(p.guid, record->EventHeader.ProviderId)) { provider = &p; break; }
    if (!provider) return;
    ++provider->seen;
    const bool fileProvider = std::string_view(provider->category) == "file";
    const unsigned schemaKey = record->EventHeader.EventDescriptor.Id |
        (static_cast<unsigned>(record->EventHeader.EventDescriptor.Version) << 16);
    std::vector<BYTE> uncached;
    auto cached = fileSchemas.find(schemaKey);
    std::vector<BYTE>* schema = fileProvider && cached != fileSchemas.end() ? &cached->second : &uncached;
    if (schema->empty()) {
      ULONG size = 0;
      ULONG status = TdhGetEventInformation(record, 0, nullptr, nullptr, &size);
      if (status != ERROR_INSUFFICIENT_BUFFER || size > 65536 || size < sizeof(TRACE_EVENT_INFO)) { ++provider->decodeErrors; return; }
      schema->resize(size);
      if (TdhGetEventInformation(record, 0, nullptr, reinterpret_cast<TRACE_EVENT_INFO*>(schema->data()), &size) != ERROR_SUCCESS) { ++provider->decodeErrors; return; }
      if (fileProvider && fileSchemas.size() < 64) schema = &fileSchemas.emplace(schemaKey, std::move(uncached)).first->second;
    }
    const auto& metadata = *schema;
    auto* info = reinterpret_cast<const TRACE_EVENT_INFO*>(metadata.data());
    antimal::EventRecord event;
    event.timestampUtc = Timestamp(record->EventHeader.TimeStamp.QuadPart);
    event.source = "GuestETW"; event.category = provider->category;
    event.action = event.category + ".etw";
    event.processId = record->EventHeader.ProcessId;
    event.details["provider"] = antimal::WideToUtf8(provider->name);
    event.details["eventId"] = std::to_string(record->EventHeader.EventDescriptor.Id);
    event.details["version"] = std::to_string(record->EventHeader.EventDescriptor.Version);
    event.details["threadId"] = std::to_string(record->EventHeader.ThreadId);
    event.details["task"] = MetadataString(metadata, info->TaskNameOffset);
    event.details["opcode"] = MetadataString(metadata, info->OpcodeNameOffset);
    const size_t count = (metadata.size() - offsetof(TRACE_EVENT_INFO, EventPropertyInfoArray)) / sizeof(EVENT_PROPERTY_INFO);
    size_t total = 0;
    for (ULONG i = 0; i < info->TopLevelPropertyCount && i < count && i < 32; ++i) {
      const auto& prop = info->EventPropertyInfoArray[i];
      if (prop.Flags & (PropertyStruct | PropertyParamCount)) { ++provider->decodeErrors; continue; }
      const auto name = MetadataString(metadata, prop.NameOffset);
      if (name.empty()) continue;
      PROPERTY_DATA_DESCRIPTOR descriptor{};
      descriptor.PropertyName = reinterpret_cast<ULONGLONG>(metadata.data() + prop.NameOffset);
      descriptor.ArrayIndex = ULONG_MAX;
      ULONG length = 0;
      if (TdhGetPropertySize(record, 0, nullptr, 1, &descriptor, &length) != ERROR_SUCCESS || length > 8192) { ++provider->decodeErrors; continue; }
      std::vector<BYTE> value(length + 2, 0);
      if (TdhGetProperty(record, 0, nullptr, 1, &descriptor, length, value.data()) != ERROR_SUCCESS) { ++provider->decodeErrors; continue; }
      std::string decoded;
      const auto type = prop.nonStructType.InType;
      if (type == TDH_INTYPE_UNICODESTRING && length % 2 == 0) {
        auto* chars = reinterpret_cast<const wchar_t*>(value.data());
        size_t n = 0; while (n < length/2 && chars[n]) ++n;
        decoded = antimal::WideToUtf8(std::wstring(chars, n));
      } else if (type == TDH_INTYPE_ANSISTRING) {
        size_t n = 0; while (n < length && value[n]) ++n;
        decoded.assign(reinterpret_cast<const char*>(value.data()), n);
      } else if (type == TDH_INTYPE_FILETIME && length == 8) {
        LONGLONG time = 0; memcpy(&time, value.data(), 8); decoded = Timestamp(time);
      } else if (type == TDH_INTYPE_BINARY && length <= 128) {
        constexpr char hex[] = "0123456789abcdef";
        decoded = "hex:";
        for (ULONG j = 0; j < length; ++j) { decoded += hex[value[j] >> 4]; decoded += hex[value[j] & 15]; }
      } else if ((type >= TDH_INTYPE_INT8 && type <= TDH_INTYPE_UINT64) ||
          type == TDH_INTYPE_POINTER || type == TDH_INTYPE_HEXINT32 || type == TDH_INTYPE_HEXINT64) {
        if (length > 0 && length <= 8) { uint64_t v = 0; memcpy(&v, value.data(), length); decoded = std::to_string(v); }
      }
      if (decoded.empty()) continue;
      total += name.size() + decoded.size();
      if (total > 12288) { ++provider->decodeErrors; break; }
      event.details["data." + name] = std::move(decoded);
    }
    auto data = [&](const char* key) { auto it = event.details.find(std::string("data.") + key); return it == event.details.end() ? std::string() : it->second; };
    if (event.category == "process") {
      auto integer = [&](const char* key) {
        const auto text = data(key); uint32_t value = 0;
        const auto result = std::from_chars(text.data(), text.data()+text.size(), value);
        return result.ec == std::errc{} && result.ptr == text.data()+text.size() ? value : 0u;
      };
      event.details["headerProcessId"] = std::to_string(event.processId);
      event.processId = integer("ProcessID");
      event.parentProcessId = integer("ParentProcessID");
      event.fullImagePath = data("ImageName");
      const auto slash = event.fullImagePath.find_last_of("\\/");
      event.imagePath = event.fullImagePath.substr(slash == std::string::npos ? 0 : slash+1);
      if (!data("CreateTime").empty()) event.details["startTime"] = data("CreateTime");
      if (!data("ExitCode").empty()) event.details["exitCode"] = data("ExitCode");
      // Keep ETW actions distinct: the polling stream still owns scorer lifetime
      // construction until cross-source instance reconciliation is validated.
    }
    if (event.category == "file") {
      std::string path = data("FileName");
      const auto object = data("FileObject");
      if (!path.empty() && !object.empty()) {
        sensitiveObjects.erase(object); // do not retain a reused object name
        if (SensitivePath(path)) {
          if (sensitiveObjects.size() >= 8192) { sensitiveObjects.clear(); ++provider->dropped; }
          sensitiveObjects[object] = path;
        }
      }
      if (path.empty() && !object.empty()) { auto it = sensitiveObjects.find(object); if (it != sensitiveObjects.end()) path = it->second; }
      if (!SensitivePath(path)) return;
      event.target = path;
      event.action = record->EventHeader.EventDescriptor.Id == 15 ? "file.read-attempt" : "file.access-observation";
      event.details["scope"] = "selected sensitive-path markers; read completion/content not proven";
    } else if (event.category == "network") {
      for (auto key : {"QueryName", "ServerName", "HostName", "Url", "URL", "RequestUrl", "ObjectName"})
        if (!data(key).empty()) { event.target = data(key); break; }
    }
    if (!queue.TryPush(std::move(event))) ++provider->dropped;
  }
};

GuestEtw::GuestEtw() : impl_(std::make_unique<Impl>()) {}
GuestEtw::~GuestEtw() = default;
void GuestEtw::Stop() { impl_->Stop(); }
std::vector<antimal::EventRecord> GuestEtw::Drain() {
  return impl_->queue.Drain();
}
std::vector<antimal::EventRecord> GuestEtw::Coverage() {
  auto& state = *impl_;
  if (state.session && ControlTraceW(state.session, kSession, state.Props(), EVENT_TRACE_CONTROL_QUERY) == ERROR_SUCCESS)
    state.osLost = static_cast<uint64_t>(state.Props()->EventsLost) + state.Props()->RealTimeBuffersLost;
  std::vector<antimal::EventRecord> out;
  for (auto& p : state.providers) {
    antimal::EventRecord e;
    e.timestampUtc = antimal::UtcNowIso8601(); e.source = "GuestETW";
    e.category = "coverage"; e.action = "agent.coverage"; e.target = p.sensor;
    e.details["supported"] = p.status == ERROR_SUCCESS ? "true" : "false";
    e.details["healthy"] = state.startStatus == ERROR_SUCCESS && p.status == ERROR_SUCCESS && state.processStatus == ERROR_SUCCESS ? "true" : "false";
    e.details["samples"] = std::to_string(p.seen.load());
    e.details["dropped"] = std::to_string(p.dropped.load() + p.decodeErrors.load() + state.osLost);
    e.details["lossKnown"] = "false"; e.details["scope"] = "system";
    e.details["note"] = "ETW provider=" + antimal::WideToUtf8(p.name) +
        "; sessionStatus=" + std::to_string(state.startStatus) + "; enableStatus=" +
        std::to_string(p.status) + "; consumerStatus=" + std::to_string(state.processStatus.load()) +
        "; decodeErrors=" + std::to_string(p.decodeErrors.load()) +
        "; queue/mapDrops=" + std::to_string(p.dropped.load()) +
        "; sessionLoss=" + std::to_string(state.osLost) +
        "; provider-dependent events, bounded fields, no HTTP payload/full injection coverage";
    out.push_back(std::move(e));
  }
  return out;
}
