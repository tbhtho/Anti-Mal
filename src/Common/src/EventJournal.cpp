#include "antimal/EventJournal.h"

#include "antimal/FileUtil.h"
#include "antimal/Json.h"

#include <Windows.h>

#include <fstream>
#include <optional>
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

namespace {

void SkipJsonWhitespace(const std::string &text, size_t &pos) {
  while (pos < text.size() &&
         (text[pos] == ' ' || text[pos] == '\t' || text[pos] == '\r' ||
          text[pos] == '\n')) {
    ++pos;
  }
}

int HexDigit(char ch) {
  if (ch >= '0' && ch <= '9') {
    return ch - '0';
  }
  if (ch >= 'a' && ch <= 'f') {
    return 10 + ch - 'a';
  }
  if (ch >= 'A' && ch <= 'F') {
    return 10 + ch - 'A';
  }
  return -1;
}

bool ParseJsonStringAt(const std::string &text, size_t &pos,
                       std::string &out) {
  SkipJsonWhitespace(text, pos);
  if (pos >= text.size() || text[pos] != '"') {
    return false;
  }
  ++pos;
  out.clear();
  while (pos < text.size()) {
    const char ch = text[pos++];
    if (ch == '"') {
      return true;
    }
    if (ch != '\\') {
      out.push_back(ch);
      continue;
    }
    if (pos >= text.size()) {
      return false;
    }
    const char esc = text[pos++];
    switch (esc) {
    case '"':
    case '\\':
    case '/':
      out.push_back(esc);
      break;
    case 'b':
      out.push_back('\b');
      break;
    case 'f':
      out.push_back('\f');
      break;
    case 'n':
      out.push_back('\n');
      break;
    case 'r':
      out.push_back('\r');
      break;
    case 't':
      out.push_back('\t');
      break;
    case 'u': {
      if (pos + 4 > text.size()) {
        return false;
      }
      int value = 0;
      for (int i = 0; i < 4; ++i) {
        const int digit = HexDigit(text[pos++]);
        if (digit < 0) {
          return false;
        }
        value = (value << 4) | digit;
      }
      out.push_back(value >= 0x20 && value <= 0x7E
                        ? static_cast<char>(value)
                        : '?');
      break;
    }
    default:
      out.push_back(esc);
      break;
    }
  }
  return false;
}

bool SkipJsonValue(const std::string &text, size_t &pos);

bool SkipJsonObject(const std::string &text, size_t &pos) {
  SkipJsonWhitespace(text, pos);
  if (pos >= text.size() || text[pos] != '{') {
    return false;
  }
  ++pos;
  SkipJsonWhitespace(text, pos);
  if (pos < text.size() && text[pos] == '}') {
    ++pos;
    return true;
  }
  while (pos < text.size()) {
    std::string key;
    if (!ParseJsonStringAt(text, pos, key)) {
      return false;
    }
    SkipJsonWhitespace(text, pos);
    if (pos >= text.size() || text[pos] != ':') {
      return false;
    }
    ++pos;
    if (!SkipJsonValue(text, pos)) {
      return false;
    }
    SkipJsonWhitespace(text, pos);
    if (pos < text.size() && text[pos] == ',') {
      ++pos;
      continue;
    }
    if (pos < text.size() && text[pos] == '}') {
      ++pos;
      return true;
    }
    return false;
  }
  return false;
}

bool SkipJsonArray(const std::string &text, size_t &pos) {
  SkipJsonWhitespace(text, pos);
  if (pos >= text.size() || text[pos] != '[') {
    return false;
  }
  ++pos;
  SkipJsonWhitespace(text, pos);
  if (pos < text.size() && text[pos] == ']') {
    ++pos;
    return true;
  }
  while (pos < text.size()) {
    if (!SkipJsonValue(text, pos)) {
      return false;
    }
    SkipJsonWhitespace(text, pos);
    if (pos < text.size() && text[pos] == ',') {
      ++pos;
      continue;
    }
    if (pos < text.size() && text[pos] == ']') {
      ++pos;
      return true;
    }
    return false;
  }
  return false;
}

bool SkipJsonValue(const std::string &text, size_t &pos) {
  SkipJsonWhitespace(text, pos);
  if (pos >= text.size()) {
    return false;
  }
  if (text[pos] == '"') {
    std::string ignored;
    return ParseJsonStringAt(text, pos, ignored);
  }
  if (text[pos] == '{') {
    return SkipJsonObject(text, pos);
  }
  if (text[pos] == '[') {
    return SkipJsonArray(text, pos);
  }
  while (pos < text.size() && text[pos] != ',' && text[pos] != '}' &&
         text[pos] != ']') {
    ++pos;
  }
  return true;
}

std::optional<size_t> FindJsonMemberValue(const std::string &text,
                                          const std::string &memberName) {
  size_t pos = 0;
  SkipJsonWhitespace(text, pos);
  if (pos >= text.size() || text[pos] != '{') {
    return std::nullopt;
  }
  ++pos;
  while (pos < text.size()) {
    SkipJsonWhitespace(text, pos);
    if (pos < text.size() && text[pos] == '}') {
      return std::nullopt;
    }

    std::string key;
    if (!ParseJsonStringAt(text, pos, key)) {
      return std::nullopt;
    }
    SkipJsonWhitespace(text, pos);
    if (pos >= text.size() || text[pos] != ':') {
      return std::nullopt;
    }
    ++pos;
    SkipJsonWhitespace(text, pos);
    if (key == memberName) {
      return pos;
    }
    if (!SkipJsonValue(text, pos)) {
      return std::nullopt;
    }
    SkipJsonWhitespace(text, pos);
    if (pos < text.size() && text[pos] == ',') {
      ++pos;
    }
  }
  return std::nullopt;
}

std::string StringMember(const std::string &line, const std::string &key) {
  auto pos = FindJsonMemberValue(line, key);
  if (!pos) {
    return {};
  }
  std::string value;
  return ParseJsonStringAt(line, *pos, value) ? value : std::string{};
}

uint32_t NumberMember(const std::string &line, const std::string &key) {
  auto pos = FindJsonMemberValue(line, key);
  if (!pos) {
    return 0;
  }
  size_t cursor = *pos;
  SkipJsonWhitespace(line, cursor);
  bool negative = false;
  if (cursor < line.size() && line[cursor] == '-') {
    negative = true;
    ++cursor;
  }
  uint64_t value = 0;
  bool sawDigit = false;
  while (cursor < line.size() && line[cursor] >= '0' && line[cursor] <= '9') {
    sawDigit = true;
    value = value * 10 + static_cast<uint64_t>(line[cursor] - '0');
    if (value > UINT32_MAX) {
      value = UINT32_MAX;
    }
    ++cursor;
  }
  if (!sawDigit || negative) {
    return 0;
  }
  return static_cast<uint32_t>(value);
}

std::map<std::string, std::string> DetailsMember(const std::string &line) {
  std::map<std::string, std::string> details;
  auto pos = FindJsonMemberValue(line, "details");
  if (!pos) {
    return details;
  }
  size_t cursor = *pos;
  SkipJsonWhitespace(line, cursor);
  if (cursor >= line.size() || line[cursor] != '{') {
    return details;
  }
  ++cursor;
  while (cursor < line.size()) {
    SkipJsonWhitespace(line, cursor);
    if (cursor < line.size() && line[cursor] == '}') {
      break;
    }
    std::string key;
    if (!ParseJsonStringAt(line, cursor, key)) {
      break;
    }
    SkipJsonWhitespace(line, cursor);
    if (cursor >= line.size() || line[cursor] != ':') {
      break;
    }
    ++cursor;
    std::string value;
    if (ParseJsonStringAt(line, cursor, value)) {
      details[std::move(key)] = std::move(value);
    } else {
      SkipJsonValue(line, cursor);
    }
    SkipJsonWhitespace(line, cursor);
    if (cursor < line.size() && line[cursor] == ',') {
      ++cursor;
    }
  }
  return details;
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
  obj.AddString("fullImagePath", event.fullImagePath);
  obj.AddString("commandLine", event.commandLine);
  obj.AddString("integrityLevel", event.integrityLevel);
  obj.AddString("userName", event.userName);
  obj.AddString("target", event.target);
  obj.AddRaw("details", details.str());
  obj.AddString("mitre", event.mitre);
  return obj.Finish() + "\n";
}

EventRecord ParseEventJsonLine(const std::string &line) {
  EventRecord event;
  event.timestampUtc = StringMember(line, "timestampUtc");
  event.source = StringMember(line, "source");
  event.category = StringMember(line, "category");
  event.action = StringMember(line, "action");
  event.processId = NumberMember(line, "processId");
  event.parentProcessId = NumberMember(line, "parentProcessId");
  event.imagePath = StringMember(line, "imagePath");
  event.fullImagePath = StringMember(line, "fullImagePath");
  event.commandLine = StringMember(line, "commandLine");
  event.integrityLevel = StringMember(line, "integrityLevel");
  event.userName = StringMember(line, "userName");
  event.target = StringMember(line, "target");
  event.details = DetailsMember(line);
  event.mitre = StringMember(line, "mitre");

  if (event.category.empty() && event.source.empty() && event.action.empty()) {
    event.category = "parse-error";
    event.target = line;
  }
  return event;
}

} // namespace antimal
