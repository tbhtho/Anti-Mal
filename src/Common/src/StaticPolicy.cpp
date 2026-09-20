#include "antimal/StaticPolicy.h"
#include "antimal/FileUtil.h"

#include <cctype>

namespace antimal {
namespace {

std::string LowerAscii(std::string v) {
  for (char &c : v) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return v;
}

// A provenance string that names a model/assistant is not an operator
// authorization and never unlocks.
bool IsModelProvenance(const std::string &by) {
  const std::string l = LowerAscii(by);
  return l.empty() || l == "assistant" || l == "model" || l == "agent" ||
         l == "ai" || l == "llm";
}

} // namespace

std::string NormalizeStaticScope(const std::string &path) {
  if (path.empty()) return {};
  std::error_code ec;
  const auto canonical = std::filesystem::weakly_canonical(Utf8ToWide(path), ec);
  if (ec) return {};
  std::string out = PathToUtf8(canonical.lexically_normal());
  for (char &c : out) {
    if (c == '\\') {
      c = '/';
    }
  }
  return LowerAscii(out);
}

bool StaticUnlock::AppliesTo(const std::string &target) const {
  if (!unlocked || scope.empty() || IsModelProvenance(authorizedBy) ||
      mechanism.empty() || recordedAt.empty()) {
    return false;
  }
  const std::string t = NormalizeStaticScope(target);
  const std::string s = NormalizeStaticScope(scope);
  if (t.empty() || s.empty()) {
    return false;
  }
  if (t == s) {
    return true;
  }
  // A directory/package scope also covers its members.
  return t.size() > s.size() && t.compare(0, s.size(), s) == 0 &&
         (s.back() == '/' || t[s.size()] == '/');
}

bool DeepStaticAllowed(const StaticUnlock &unlock, const std::string &target,
                       std::string *reason) {
  if (unlock.AppliesTo(target)) {
    return true;
  }
  if (reason != nullptr) {
    if (!unlock.unlocked) {
      *reason =
          "deep static enrichment is locked by default; an explicit operator "
          "unlock scoped to this target is required (CLI: --unlock-static)";
    } else if (IsModelProvenance(unlock.authorizedBy)) {
      *reason =
          "deep static enrichment is locked: the recorded authorization is not "
          "an operator request (a model/assistant cannot authorize itself)";
    } else if (unlock.scope.empty()) {
      *reason =
          "the operator unlock has no scope; it cannot apply to this target";
    } else if (unlock.mechanism.empty() || unlock.recordedAt.empty()) {
      *reason = "the operator unlock lacks a recorded mechanism or timestamp";
    } else {
      *reason = "the operator unlock is scoped to '" + unlock.scope +
                "', not to this target";
    }
  }
  return false;
}

const char *StaticAnalysisLockedLabel() { return "Not run - locked"; }

const char *StaticAnalysisLockedSummary() {
  return "Deep static enrichment is locked by default. Antimal is a dynamic "
         "analysis environment: static-only work does not complete a requested "
         "dynamic investigation. Basic identity/inventory (path, size, hashes, "
         "file type, bounded metadata) was collected.";
}

} // namespace antimal
