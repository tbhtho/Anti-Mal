#pragma once

// Minimal, dependency-free JSON value parser. Json.h already provides
// serialization (ToJson / JsonObjectBuilder / JsonEscape); this is the read
// side, used by the WebView2 bridge to parse inbound command envelopes. It is
// deliberately small and defensive (depth + size caps) because it parses
// guest/UI-controlled input (see the live-sandbox-console security model).

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace antimal {

class JsonValue {
public:
  enum class Type { Null, Bool, Number, String, Array, Object };

  Type type = Type::Null;
  bool boolean = false;
  double number = 0.0;
  std::string str;
  std::vector<JsonValue> array;
  std::map<std::string, JsonValue> object;

  bool IsNull() const { return type == Type::Null; }
  bool IsBool() const { return type == Type::Bool; }
  bool IsNumber() const { return type == Type::Number; }
  bool IsString() const { return type == Type::String; }
  bool IsArray() const { return type == Type::Array; }
  bool IsObject() const { return type == Type::Object; }

  bool AsBool() const { return type == Type::Bool && boolean; }
  int64_t AsInt64() const { return static_cast<int64_t>(number); }
  double AsNumber() const { return number; }
  const std::string &AsString() const { return str; }

  // Safe object accessor: returns a static Null sentinel when this is not an
  // object or the key is absent (so callers can chain .At(...).AsString()
  // without null checks or exceptions).
  const JsonValue &At(const std::string &key) const;
  bool Has(const std::string &key) const {
    return type == Type::Object && object.count(key) != 0;
  }
};

// Parses a complete JSON document. Returns std::nullopt on any malformed input,
// trailing garbage, empty input, oversized input, or excessive nesting. Never
// throws.
std::optional<JsonValue> ParseJson(const std::string &text);

} // namespace antimal
