#include "antimal/JsonValue.h"

#include <cstdlib>

namespace antimal {

const JsonValue &JsonValue::At(const std::string &key) const {
  static const JsonValue kNull;
  if (type != Type::Object) {
    return kNull;
  }
  const auto it = object.find(key);
  return it == object.end() ? kNull : it->second;
}

namespace {

constexpr int kMaxDepth = 64;
constexpr size_t kMaxInput = 8u * 1024u * 1024u;

// Single-pass recursive-descent parser. `ok` latches false on the first error
// so callers can bail without exceptions.
struct Parser {
  const std::string &s;
  size_t pos = 0;
  bool ok = true;

  explicit Parser(const std::string &text) : s(text) {}

  bool fail() {
    ok = false;
    return false;
  }

  void skipWs() {
    while (pos < s.size()) {
      const char c = s[pos];
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
        ++pos;
      } else {
        break;
      }
    }
  }

  bool literal(const char *lit) {
    size_t n = 0;
    while (lit[n] != '\0') {
      ++n;
    }
    if (pos + n > s.size()) {
      return fail();
    }
    for (size_t i = 0; i < n; ++i) {
      if (s[pos + i] != lit[i]) {
        return fail();
      }
    }
    pos += n;
    return true;
  }

  static void appendUtf8(std::string &dest, unsigned code) {
    if (code < 0x80u) {
      dest.push_back(static_cast<char>(code));
    } else if (code < 0x800u) {
      dest.push_back(static_cast<char>(0xC0u | (code >> 6)));
      dest.push_back(static_cast<char>(0x80u | (code & 0x3Fu)));
    } else {
      dest.push_back(static_cast<char>(0xE0u | (code >> 12)));
      dest.push_back(static_cast<char>(0x80u | ((code >> 6) & 0x3Fu)));
      dest.push_back(static_cast<char>(0x80u | (code & 0x3Fu)));
    }
  }

  bool parseString(std::string &dest) {
    if (pos >= s.size() || s[pos] != '"') {
      return fail();
    }
    ++pos;
    while (pos < s.size()) {
      const char c = s[pos++];
      if (c == '"') {
        return true;
      }
      if (c == '\\') {
        if (pos >= s.size()) {
          return fail();
        }
        const char e = s[pos++];
        switch (e) {
        case '"': dest.push_back('"'); break;
        case '\\': dest.push_back('\\'); break;
        case '/': dest.push_back('/'); break;
        case 'b': dest.push_back('\b'); break;
        case 'f': dest.push_back('\f'); break;
        case 'n': dest.push_back('\n'); break;
        case 'r': dest.push_back('\r'); break;
        case 't': dest.push_back('\t'); break;
        case 'u': {
          if (pos + 4 > s.size()) {
            return fail();
          }
          unsigned code = 0;
          for (int i = 0; i < 4; ++i) {
            const char h = s[pos++];
            code <<= 4;
            if (h >= '0' && h <= '9') {
              code |= static_cast<unsigned>(h - '0');
            } else if (h >= 'a' && h <= 'f') {
              code |= static_cast<unsigned>(h - 'a' + 10);
            } else if (h >= 'A' && h <= 'F') {
              code |= static_cast<unsigned>(h - 'A' + 10);
            } else {
              return fail();
            }
          }
          appendUtf8(dest, code); // BMP only; surrogate pairs encoded separately
          break;
        }
        default:
          return fail();
        }
      } else {
        dest.push_back(c);
      }
    }
    return fail(); // unterminated string
  }

  bool parseNumber(JsonValue &out) {
    const size_t start = pos;
    if (pos < s.size() && s[pos] == '-') {
      ++pos;
    }
    while (pos < s.size()) {
      const char c = s[pos];
      if ((c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' ||
          c == '+' || c == '-') {
        ++pos;
      } else {
        break;
      }
    }
    if (pos == start) {
      return fail();
    }
    const std::string num = s.substr(start, pos - start);
    char *end = nullptr;
    const double v = std::strtod(num.c_str(), &end);
    if (end == num.c_str() || *end != '\0') {
      return fail();
    }
    out.type = JsonValue::Type::Number;
    out.number = v;
    return true;
  }

  bool parseArray(JsonValue &out, int depth) {
    out.type = JsonValue::Type::Array;
    ++pos; // consume '['
    skipWs();
    if (pos < s.size() && s[pos] == ']') {
      ++pos;
      return true;
    }
    while (true) {
      JsonValue item;
      if (!parseValue(item, depth + 1)) {
        return false;
      }
      out.array.push_back(std::move(item));
      skipWs();
      if (pos >= s.size()) {
        return fail();
      }
      if (s[pos] == ',') {
        ++pos;
        continue;
      }
      if (s[pos] == ']') {
        ++pos;
        return true;
      }
      return fail();
    }
  }

  bool parseObject(JsonValue &out, int depth) {
    out.type = JsonValue::Type::Object;
    ++pos; // consume '{'
    skipWs();
    if (pos < s.size() && s[pos] == '}') {
      ++pos;
      return true;
    }
    while (true) {
      skipWs();
      std::string key;
      if (!parseString(key)) {
        return false;
      }
      skipWs();
      if (pos >= s.size() || s[pos] != ':') {
        return fail();
      }
      ++pos;
      JsonValue val;
      if (!parseValue(val, depth + 1)) {
        return false;
      }
      out.object[key] = std::move(val);
      skipWs();
      if (pos >= s.size()) {
        return fail();
      }
      if (s[pos] == ',') {
        ++pos;
        continue;
      }
      if (s[pos] == '}') {
        ++pos;
        return true;
      }
      return fail();
    }
  }

  bool parseValue(JsonValue &out, int depth) {
    if (depth > kMaxDepth) {
      return fail();
    }
    skipWs();
    if (pos >= s.size()) {
      return fail();
    }
    const char c = s[pos];
    switch (c) {
    case '{':
      return parseObject(out, depth);
    case '[':
      return parseArray(out, depth);
    case '"':
      out.type = JsonValue::Type::String;
      return parseString(out.str);
    case 't':
    case 'f': {
      if (c == 't') {
        if (!literal("true")) {
          return false;
        }
        out.boolean = true;
      } else {
        if (!literal("false")) {
          return false;
        }
        out.boolean = false;
      }
      out.type = JsonValue::Type::Bool;
      return true;
    }
    case 'n':
      if (!literal("null")) {
        return false;
      }
      out.type = JsonValue::Type::Null;
      return true;
    default:
      if (c == '-' || (c >= '0' && c <= '9')) {
        return parseNumber(out);
      }
      return fail();
    }
  }
};

} // namespace

std::optional<JsonValue> ParseJson(const std::string &text) {
  if (text.empty() || text.size() > kMaxInput) {
    return std::nullopt;
  }
  Parser p(text);
  JsonValue root;
  if (!p.parseValue(root, 0) || !p.ok) {
    return std::nullopt;
  }
  p.skipWs();
  if (p.pos != text.size()) {
    return std::nullopt; // trailing garbage
  }
  return root;
}

} // namespace antimal
