// Benign guest-only controller. Creates synthetic decoys without overwriting
// existing files, records workflow phases, and launches the installed target.
// Never execute this controller on the owner's host.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <wincrypt.h>
#include <winsqlite/winsqlite3.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
static std::ofstream logFile;
static void Log(const std::string& phase, DWORD pid = 0) {
  SYSTEMTIME t{}; GetSystemTime(&t); char time[40]{};
  sprintf_s(time, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", t.wYear,t.wMonth,t.wDay,t.wHour,t.wMinute,t.wSecond,t.wMilliseconds);
  logFile << time << '\t' << phase << '\t' << pid << '\n'; logFile.flush();
}
static bool Reserve(const fs::path& path) {
  std::error_code ec; fs::create_directories(path.parent_path(),ec);
  HANDLE f = CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
  if (f==INVALID_HANDLE_VALUE) { Log("decoy-skipped-existing-or-error:"+path.filename().string()); return false; }
  CloseHandle(f); return true;
}
static void DecoyText(const fs::path& path, const char* text) {
  if (!Reserve(path)) return;
  std::ofstream f(path,std::ios::binary); f << text; f.close();
  Log("synthetic-decoy-created:"+path.string());
}
static void LoginDecoy(const fs::path& path) {
  if (!Reserve(path)) return;
  sqlite3* db=nullptr;
  if (sqlite3_open16(path.c_str(),&db)!=SQLITE_OK) { if(db)sqlite3_close(db); Log("decoy-db-open-failed"); return; }
  const char* sql="CREATE TABLE logins(origin_url TEXT,action_url TEXT,username_value TEXT,password_value BLOB,signon_realm TEXT);";
  if(sqlite3_exec(db,sql,nullptr,nullptr,nullptr)!=SQLITE_OK) {sqlite3_close(db);Log("decoy-schema-failed");return;}
  char synthetic[]="ANTIMAL_SYNTHETIC_PASSWORD_NOT_A_REAL_ACCOUNT";
  DATA_BLOB plain{sizeof(synthetic),reinterpret_cast<BYTE*>(synthetic)}, encrypted{};
  if(CryptProtectData(&plain,L"AntiMal synthetic decoy",nullptr,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&encrypted)) {
    sqlite3_stmt* insert=nullptr;
    if(sqlite3_prepare_v2(db,"INSERT INTO logins VALUES('https://antimal-decoy.invalid/','https://antimal-decoy.invalid/','synthetic-user',?,'https://antimal-decoy.invalid/');",-1,&insert,nullptr)==SQLITE_OK) {
      sqlite3_bind_blob(insert,1,encrypted.pbData,static_cast<int>(encrypted.cbData),SQLITE_TRANSIENT);
      Log(sqlite3_step(insert)==SQLITE_DONE ? "synthetic-login-row-created" : "decoy-insert-failed");
      sqlite3_finalize(insert);
    }
    LocalFree(encrypted.pbData);
  } else Log("decoy-encryption-failed");
  sqlite3_close(db);
}
int WINAPI wWinMain(HINSTANCE,HINSTANCE,PWSTR,int) {
  wchar_t computer[128]{}; DWORD size=128;
  if(!GetComputerNameW(computer,&size)||_wcsicmp(computer,L"ANTIMAL-VM")!=0) return 90;
  wchar_t profile[32768]{};
  if(!GetEnvironmentVariableW(L"USERPROFILE",profile,32768)) return 91;
  const fs::path base=L"C:\\Users\\Public\\AntiMalSynthetic";
  std::error_code ec; fs::create_directories(base,ec);
  const auto log=base/L"afterfx-workflow.tsv";
  if(!Reserve(log)) return 92;
  logFile.open(log); Log("controller-start",GetCurrentProcessId());
  const fs::path user=profile;
  LoginDecoy(user/L"AppData/Local/Google/Chrome/User Data/Default/Login Data");
  DecoyText(user/L"AppData/Local/Google/Chrome/User Data/Local State","{\"antimal_synthetic\":true,\"note\":\"Not a real browser account\"}");
  DecoyText(user/L"AppData/Roaming/discord/Local Storage/leveldb/000001.ldb","ANTIMAL_SYNTHETIC_SESSION_TOKEN_NOT_VALID");
  DecoyText(user/L"AppData/Roaming/Exodus/exodus.wallet/wallet-decoy.txt","ANTIMAL_SYNTHETIC_WALLET_NOT_VALID");
  DecoyText(user/L"Desktop/wallet-synthetic-passwords.txt","ANTIMAL_SYNTHETIC_PASSWORD_NOT_A_REAL_ACCOUNT");
  // Positive control for the existing selected-path read sensor, attributed
  // to this benign controller before baseline (never to After Effects).
  const auto login=user/L"AppData/Local/Google/Chrome/User Data/Default/Login Data";
  HANDLE probe=CreateFileW(login.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);
  if(probe!=INVALID_HANDLE_VALUE) {
    char bytes[128]{};DWORD read=0;
    const BOOL ok=ReadFile(probe,bytes,sizeof(bytes),&read,nullptr);CloseHandle(probe);
    Log("decoy-read-positive-control-"+std::to_string(ok ? read : 0),GetCurrentProcessId());
  } else Log("decoy-read-positive-control-failed",GetCurrentProcessId());
  Log("baseline-start"); Sleep(60000); Log("baseline-end");
  const fs::path target=L"C:\\Program Files\\Adobe\\Adobe After Effects 2020\\Support Files\\AfterFX.exe";
  if(!fs::is_regular_file(target,ec)) {Log("target-missing");return 93;}
  for(unsigned cycle=1;cycle<=2;++cycle) {
    std::wstring command=L"\""+target.wstring()+L"\"";
    std::vector<wchar_t> writable(command.begin(),command.end());writable.push_back(0);
    STARTUPINFOW startup{};startup.cb=sizeof(startup);PROCESS_INFORMATION process{};
    Log("launch-request-"+std::to_string(cycle));
    if(!CreateProcessW(target.c_str(),writable.data(),nullptr,nullptr,FALSE,0,nullptr,target.parent_path().c_str(),&startup,&process)) {
      Log("launch-failed-"+std::to_string(GetLastError()));return 94;
    }
    CloseHandle(process.hThread);Log("application-start-"+std::to_string(cycle),process.dwProcessId);
    DWORD wait=WaitForSingleObject(process.hProcess,12*60*1000);
    if(wait!=WAIT_OBJECT_0) {Log("workflow-timeout-unfinished",process.dwProcessId);CloseHandle(process.hProcess);return 95;}
    DWORD exit=0;GetExitCodeProcess(process.hProcess,&exit);CloseHandle(process.hProcess);
    Log("application-exit-"+std::to_string(cycle)+"-code-"+std::to_string(exit),process.dwProcessId);
    if(cycle==1) {Log("between-sessions-baseline");Sleep(30000);}
  }
  Log("two-application-sessions-finished");Sleep(60000);Log("controller-complete");return 0;
}
