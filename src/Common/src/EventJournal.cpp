#include "antimal/EventJournal.h"

#include "antimal/FileUtil.h"
#include "antimal/Json.h"

#include <Windows.h>

#include <fstream>
#include <regex>
#include <stdexcept>

namespace antimal {

EventJournalWriter::EventJournalWriter(const std::filesystem::path &path)
    : path_(path) {
  EnsureDirectory(path.parent_path());
  // "ab" — append in binary mode so newline conversion doesn't trample
  // our \n-terminated records.
  errno_t err = _wfopen_s(&file_, path.wstring().c_str(), L"ab");
  if (err != 0 || !file_) {
    throw std::runtime_error("EventJournalWriter: failed to open " +
                             PathToUtf8(path));
  }
}

EventJournalWriter::~EventJournalWriter() {
  if (file_) std::fclose(file_);
}

void EventJournalWriter::Append(const EventRecord &event) {
  if (!file_) return;
  const auto line = SerializeEventJsonLine(event);
  std::lock_guard<std::mutex> guard(mu_);
  std::fwrite(line.data(), 1, line.size(), file_);
  std::fflush(file_);
}

EventJournalTailer::EventJournalTailer(const std::filesystem::path &path)
    : path_(path) {}

namespace {

std::vector<EventRecord> ReadFromOffset(const std::filesystem::path &path,
                                        std::uintmax_t offset,
                                        std::string &remainder,
                                        std::uintmax_t *newCursor) {
  std::vector<EventRecord> out;
  std::error_code ec;
  if (!std::filesystem::exists(path, ec)) {
    return out;
  }
  std::ifstream stream(path, std::ios::binary);
  if (!stream) return out;
  stream.seekg(0, std::ios::end);
  const auto end = static_cast<std::uintmax_t>(stream.tellg());
  if (end <= offset) {
    if (newCursor) *newCursor = offset;
    return out;
  }
  stream.seekg(offset);
  std::string buffer(end - offset, '\0');
  stream.read(buffer.data(), buffer.size());
  buffer.resize(static_cast<size_t>(stream.gcount()));
  if (newCursor) *newCursor = end;

  // Prepend any partial line we were carrying.
  std::string combined = remainder + buffer;
  remainder.clear();

  size_t lineStart = 0;
  for (size_t i = 0; i < combined.size(); ++i) {
    if (combined[i] != '\n') continue;
    size_t lineEnd = i;
    if (lineEnd > lineStart && combined[lineEnd - 1] == '\r') --lineEnd;
    if (lineEnd > lineStart) {
      out.push_back(ParseEventJsonLine(
          combined.substr(lineStart, lineEnd - lineStart)));
    }
    lineStart = i + 1;
  }
  if (lineStart < combined.size()) {
    remainder = combined.substr(lineStart);
  }
  return out;
}

} // namespace

std::vector<EventRecord> EventJournalTailer::PullNew() {
  std::uintmax_t newCursor = cursor_;
  auto events = ReadFromOffset(path_, cursor_, remainder_, &newCursor);
  cursor_ = newCursor;
  return events;
}

std::vector<EventRecord> EventJournalTailer::ReadAll() {
  std::string remainder;
  std::uintmax_t newCursor = 0;
  return ReadFromOffset(path_, 0, remainder, &newCursor);
}

std::string SerializeEventJsonLine(const EventRecord &event) {
  std::ostringstream details;
  details << "{";
  size_t i = 0;
  for (const auto &[key, value] : event.details) {
    if (i++) details << ",";
    details << JsonQuote(key) << ":" << JsonQuote(value);
  }
  details << "}";

  JsonObjectBuilder obj;
  obj.AddString("timestampUtc", event.timestampUtc.empty() ? UtcNowIso8601()
                                                           : event.timestampUtc);
  obj.AddString("source", event.source);
  obj.AddString("category", event.category);
  obj.AddString("action", event.action);
  obj.AddNumber("processId", event.processId);
  obj.AddNumber("parentProcessId", event.parentProcessId);
  obj.AddString("imagePath", event.imagePath);
  obj.AddString("target", event.target);
  obj.AddRaw("details", details.str());
  obj.AddString("mitre", event.mitre);
  return obj.Finish() + "\n";
}

EventRecord ParseEventJsonLine(const std::string &line) {
  EventRecord event;
  auto stringField = [&](const std::string &key) {
    std::regex re("\"" + key + "\"\\s*:\\s*\"([^\"\\\\]*(?:\\\\.[^\"\\\\]*)*)\"");
    std::smatch m;
    if (std::regex_search(line, m, re)) return m[1].str();
    return std::string{};
  };
  auto numberField = [&](const std::string &key) -> uint32_t {
    std::regex re("\"" + key + "\"\\s*:\\s*(-?\\d+)");
    std::smatch m;
    if (std::regex_search(line, m, re)) return static_cast<uint32_t>(std::stoul(m[1].str()));
    return 0u;
  };
  event.timestampUtc = stringField("timestampUtc");
  event.source = stringField("source");
  event.category = stringField("category");
  event.action = stringField("action");
  event.processId = numberField("processId");
  event.parentProcessId = numberField("parentProcessId");
  event.imagePath = stringField("imagePath");
  event.target = stringField("target");
  event.mitre = stringField("mitre");

  // Parse the "details" inner object into key/value pairs.
  std::regex detailsRe(R"("details"\s*:\s*\{([^}]*)\})");
  std::smatch dm;
  if (std::regex_search(line, dm, detailsRe)) {
    const std::string body = dm[1].str();
    std::regex pairRe("\"([^\"\\\\]*(?:\\\\.[^\"\\\\]*)*)\"\\s*:\\s*\"([^\"\\\\]*(?:\\\\.[^\"\\\\]*)*)\"");
    for (auto it = std::sregex_iterator(body.begin(), body.end(), pairRe);
         it != std::sregex_iterator(); ++it) {
      event.details[(*it)[1].str()] = (*it)[2].str();
    }
  }

  if (event.category.empty() && event.source.empty() && event.action.empty()) {
    event.category = "parse-error";
    event.target = line;
  }
  return event;
}

} // namespace antimal
