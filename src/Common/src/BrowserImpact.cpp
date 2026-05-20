#include "antimal/BrowserImpact.h"

#include "antimal/Crypto.h"
#include "antimal/FileUtil.h"

#include <Windows.h>
#include <winsqlite/winsqlite3.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <regex>
#include <set>

namespace antimal {
namespace {

std::optional<std::filesystem::path> EnvPath(const wchar_t *name) {
  size_t needed = 0;
  _wgetenv_s(&needed, nullptr, 0, name);
  if (!needed) {
    return std::nullopt;
  }
  std::wstring value(needed, L'\0');
  _wgetenv_s(&needed, value.data(), value.size(), name);
  while (!value.empty() && value.back() == L'\0') {
    value.pop_back();
  }
  return std::filesystem::path(value);
}

std::vector<std::filesystem::path> CandidateChromiumRoots() {
  std::vector<std::filesystem::path> roots;
  const auto local = EnvPath(L"LOCALAPPDATA");
  if (!local) {
    return roots;
  }
  roots.push_back(*local / "Google" / "Chrome" / "User Data");
  roots.push_back(*local / "Microsoft" / "Edge" / "User Data");
  roots.push_back(*local / "BraveSoftware" / "Brave-Browser" / "User Data");
  return roots;
}

std::vector<std::filesystem::path> CandidateProfiles(const std::filesystem::path &root) {
  std::vector<std::filesystem::path> profiles;
  if (!std::filesystem::exists(root)) {
    return profiles;
  }
  for (const auto &entry : std::filesystem::directory_iterator(root)) {
    if (!entry.is_directory()) {
      continue;
    }
    const auto name = entry.path().filename().wstring();
    if (name == L"Default" || name.rfind(L"Profile ", 0) == 0) {
      profiles.push_back(entry.path());
    }
  }
  return profiles;
}

std::vector<uint8_t> Base64Decode(std::string_view input) {
  static constexpr unsigned char kInvalid = 0xff;
  std::array<unsigned char, 256> table{};
  table.fill(kInvalid);
  const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  for (size_t i = 0; i < chars.size(); ++i) {
    table[static_cast<unsigned char>(chars[i])] = static_cast<unsigned char>(i);
  }

  std::vector<uint8_t> out;
  int val = 0;
  int valb = -8;
  for (unsigned char c : input) {
    if (std::isspace(c) || c == '=') {
      continue;
    }
    if (table[c] == kInvalid) {
      break;
    }
    val = (val << 6) + table[c];
    valb += 6;
    if (valb >= 0) {
      out.push_back(static_cast<uint8_t>((val >> valb) & 0xff));
      valb -= 8;
    }
  }
  return out;
}

std::optional<std::vector<uint8_t>> LoadChromiumMasterKey(const std::filesystem::path &root) {
  const auto localState = root / "Local State";
  if (!std::filesystem::exists(localState)) {
    return std::nullopt;
  }
  const std::string text = ReadTextFile(localState);
  std::regex keyRegex("\"encrypted_key\"\\s*:\\s*\"([^\"]+)\"");
  std::smatch match;
  if (!std::regex_search(text, match, keyRegex)) {
    return std::nullopt;
  }
  auto encrypted = Base64Decode(match[1].str());
  const std::string dpapiPrefix = "DPAPI";
  if (encrypted.size() > dpapiPrefix.size() &&
      std::equal(dpapiPrefix.begin(), dpapiPrefix.end(), encrypted.begin())) {
    encrypted.erase(encrypted.begin(), encrypted.begin() + dpapiPrefix.size());
  }
  return DpapiUnprotect(encrypted);
}

std::optional<std::vector<uint8_t>> TryDecryptChromiumBlob(
    const std::vector<uint8_t> &blob, const std::optional<std::vector<uint8_t>> &masterKey) {
  if (blob.empty()) {
    return std::nullopt;
  }
  if (blob.size() > 3 && blob[0] == 'v' && blob[1] == '1' &&
      (blob[2] == '0' || blob[2] == '1') && masterKey) {
    if (blob.size() <= 3 + 12 + 16) {
      return std::nullopt;
    }
    std::vector<uint8_t> nonce(blob.begin() + 3, blob.begin() + 15);
    std::vector<uint8_t> tag(blob.end() - 16, blob.end());
    std::vector<uint8_t> ciphertext(blob.begin() + 15, blob.end() - 16);
    return AesGcmDecrypt(*masterKey, nonce, ciphertext, tag);
  }
  return DpapiUnprotect(blob);
}

std::filesystem::path CopyDbToTemp(const std::filesystem::path &db) {
  const auto tempRoot = std::filesystem::temp_directory_path() / ("antimal-" + MakeRunId());
  EnsureDirectory(tempRoot);
  const auto tempDb = tempRoot / db.filename();
  std::error_code ec;
  std::filesystem::copy_file(db, tempDb, std::filesystem::copy_options::overwrite_existing, ec);
  if (ec) {
    return db;
  }
  return tempDb;
}

class SqliteDb {
public:
  explicit SqliteDb(const std::filesystem::path &path) {
    if (sqlite3_open16(path.wstring().c_str(), &db_) != SQLITE_OK) {
      db_ = nullptr;
    }
  }
  ~SqliteDb() {
    if (db_) {
      sqlite3_close(db_);
    }
  }
  sqlite3 *get() const { return db_; }
  explicit operator bool() const { return db_ != nullptr; }

private:
  sqlite3 *db_ = nullptr;
};

std::vector<uint8_t> ColumnBlob(sqlite3_stmt *stmt, int column) {
  const auto *blob = static_cast<const uint8_t *>(sqlite3_column_blob(stmt, column));
  const int size = sqlite3_column_bytes(stmt, column);
  if (!blob || size <= 0) {
    return {};
  }
  return {blob, blob + size};
}

std::string ColumnText(sqlite3_stmt *stmt, int column) {
  const auto *text = reinterpret_cast<const char *>(sqlite3_column_text(stmt, column));
  return text ? std::string(text) : std::string();
}

void AddOrMerge(std::vector<BrowserRisk> &risks, BrowserRisk risk) {
  if (risk.domain.empty()) {
    return;
  }
  for (auto &existing : risks) {
    if (existing.domain == risk.domain) {
      existing.savedCredentials = existing.savedCredentials || risk.savedCredentials;
      existing.cookiesPresent = existing.cookiesPresent || risk.cookiesPresent;
      existing.decryptedEvidenceAvailable =
          existing.decryptedEvidenceAvailable || risk.decryptedEvidenceAvailable;
      if (existing.lastVisited.empty()) {
        existing.lastVisited = risk.lastVisited;
      }
      return;
    }
  }
  risks.push_back(std::move(risk));
}

void QueryHistory(const std::filesystem::path &profile, std::vector<BrowserRisk> &risks) {
  const auto historyPath = profile / "History";
  if (!std::filesystem::exists(historyPath)) {
    return;
  }
  SqliteDb db(CopyDbToTemp(historyPath));
  if (!db) {
    return;
  }
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db.get(),
                         "SELECT url, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 5000",
                         -1, &stmt, nullptr) != SQLITE_OK) {
    return;
  }
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    BrowserRisk risk;
    risk.domain = ExtractDomain(ColumnText(stmt, 0));
    risk.site = risk.domain;
    risk.lastVisited = std::to_string(static_cast<long long>(sqlite3_column_int64(stmt, 1)));
    AddOrMerge(risks, risk);
  }
  sqlite3_finalize(stmt);
}

void QueryCookies(const std::filesystem::path &profile, const std::optional<std::vector<uint8_t>> &key,
                  bool decrypt, std::vector<BrowserRisk> &risks) {
  const auto cookiesPath = profile / "Network" / "Cookies";
  if (!std::filesystem::exists(cookiesPath)) {
    return;
  }
  SqliteDb db(CopyDbToTemp(cookiesPath));
  if (!db) {
    return;
  }
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db.get(),
                         "SELECT host_key, encrypted_value FROM cookies LIMIT 5000", -1,
                         &stmt, nullptr) != SQLITE_OK) {
    return;
  }
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    BrowserRisk risk;
    risk.domain = ExtractDomain(ColumnText(stmt, 0));
    risk.site = risk.domain;
    risk.cookiesPresent = true;
    if (decrypt) {
      const auto plain = TryDecryptChromiumBlob(ColumnBlob(stmt, 1), key);
      risk.decryptedEvidenceAvailable = plain && !plain->empty();
    }
    AddOrMerge(risks, risk);
  }
  sqlite3_finalize(stmt);
}

void QueryLogins(const std::filesystem::path &profile, const std::optional<std::vector<uint8_t>> &key,
                 bool decrypt, std::vector<BrowserRisk> &risks) {
  const auto loginPath = profile / "Login Data";
  if (!std::filesystem::exists(loginPath)) {
    return;
  }
  SqliteDb db(CopyDbToTemp(loginPath));
  if (!db) {
    return;
  }
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db.get(),
                         "SELECT origin_url, password_value FROM logins LIMIT 5000", -1,
                         &stmt, nullptr) != SQLITE_OK) {
    return;
  }
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    BrowserRisk risk;
    risk.domain = ExtractDomain(ColumnText(stmt, 0));
    risk.site = risk.domain;
    risk.savedCredentials = true;
    if (decrypt) {
      const auto plain = TryDecryptChromiumBlob(ColumnBlob(stmt, 1), key);
      risk.decryptedEvidenceAvailable = plain && !plain->empty();
    }
    AddOrMerge(risks, risk);
  }
  sqlite3_finalize(stmt);
}

bool DomainMatches(const std::set<std::string> &contacted, const std::string &domain) {
  if (domain.empty()) {
    return false;
  }
  for (const auto &item : contacted) {
    if (domain == item || (domain.size() > item.size() &&
                           domain.ends_with("." + item))) {
      return true;
    }
    if (item.size() > domain.size() && item.ends_with("." + domain)) {
      return true;
    }
  }
  return false;
}

} // namespace

std::string ExtractDomain(std::string_view urlOrHost) {
  std::string value = ToLowerAscii(std::string(urlOrHost));
  value = Trim(value);
  if (value.empty()) {
    return {};
  }
  const auto scheme = value.find("://");
  if (scheme != std::string::npos) {
    value.erase(0, scheme + 3);
  }
  if (value.starts_with(".")) {
    value.erase(0, 1);
  }
  const auto slash = value.find_first_of("/?#");
  if (slash != std::string::npos) {
    value.erase(slash);
  }
  const auto at = value.rfind('@');
  if (at != std::string::npos) {
    value.erase(0, at + 1);
  }
  const auto colon = value.find(':');
  if (colon != std::string::npos && value.find(']') == std::string::npos) {
    value.erase(colon);
  }
  if (value.starts_with("www.")) {
    value.erase(0, 4);
  }
  return value;
}

std::set<std::string> NormalizeDomains(const std::vector<std::string> &domains) {
  std::set<std::string> normalized;
  for (const auto &domain : domains) {
    const auto extracted = ExtractDomain(domain);
    if (!extracted.empty()) {
      normalized.insert(extracted);
    }
  }
  return normalized;
}

std::vector<BrowserRisk> AnalyzeBrowserImpactFromSyntheticData(
    const std::vector<std::string> &contactedDomains,
    const std::vector<BrowserRisk> &browserRecords) {
  const auto contacted = NormalizeDomains(contactedDomains);
  std::vector<BrowserRisk> risks;
  for (auto risk : browserRecords) {
    risk.domain = ExtractDomain(risk.domain.empty() ? risk.site : risk.domain);
    risk.contactedBySample = DomainMatches(contacted, risk.domain);
    if (!risk.contactedBySample) {
      continue;
    }
    if (risk.savedCredentials && risk.cookiesPresent) {
      risk.recommendation = "Change password and revoke active sessions.";
    } else if (risk.savedCredentials) {
      risk.recommendation = "Change password and enable multi-factor authentication.";
    } else if (risk.cookiesPresent) {
      risk.recommendation = "Revoke sessions and clear browser cookies.";
    } else {
      risk.recommendation = "Review account activity.";
    }
    risks.push_back(std::move(risk));
  }
  return risks;
}

std::vector<BrowserRisk> AnalyzeBrowserImpact(const std::vector<std::string> &contactedDomains,
                                              bool decryptBrowserSecrets) {
  std::vector<BrowserRisk> records;
  for (const auto &root : CandidateChromiumRoots()) {
    const auto key = LoadChromiumMasterKey(root);
    for (const auto &profile : CandidateProfiles(root)) {
      QueryHistory(profile, records);
      QueryCookies(profile, key, decryptBrowserSecrets, records);
      QueryLogins(profile, key, decryptBrowserSecrets, records);
    }
  }
  return AnalyzeBrowserImpactFromSyntheticData(contactedDomains, records);
}

} // namespace antimal
