#include "antimal/MitreCatalog.h"

#include <unordered_map>

namespace antimal {

std::string MitreTechniqueName(const std::string &id) {
  // Curated subset of ATT&CK Enterprise techniques relevant to AntiMal's
  // behavior/capa mapping, config extraction, and the simulation. Sub-technique
  // names are prefixed with their parent for context.
  static const std::unordered_map<std::string, std::string> kCatalog = {
      // Execution
      {"T1059", "Command and Scripting Interpreter"},
      {"T1059.001", "Command and Scripting Interpreter: PowerShell"},
      {"T1059.003", "Command and Scripting Interpreter: Windows Command Shell"},
      {"T1059.005", "Command and Scripting Interpreter: Visual Basic"},
      {"T1059.007", "Command and Scripting Interpreter: JavaScript"},
      {"T1106", "Native API"},
      {"T1204", "User Execution"},
      {"T1204.002", "User Execution: Malicious File"},
      {"T1047", "Windows Management Instrumentation"},
      {"T1053", "Scheduled Task/Job"},
      {"T1053.005", "Scheduled Task/Job: Scheduled Task"},
      {"T1569.002", "System Services: Service Execution"},
      // Persistence
      {"T1547", "Boot or Logon Autostart Execution"},
      {"T1547.001",
       "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder"},
      {"T1547.004", "Boot or Logon Autostart Execution: Winlogon Helper DLL"},
      {"T1547.014", "Boot or Logon Autostart Execution: Active Setup"},
      {"T1543.003", "Create or Modify System Process: Windows Service"},
      {"T1546.010", "Event Triggered Execution: AppInit DLLs"},
      {"T1546.012", "Event Triggered Execution: Image File Execution Options Injection"},
      {"T1546", "Event Triggered Execution"},
      {"T1546.015", "Event Triggered Execution: Component Object Model Hijacking"},
      {"T1574", "Hijack Execution Flow"},
      {"T1574.002", "Hijack Execution Flow: DLL Side-Loading"},
      // Privilege Escalation / Defense Evasion
      {"T1055", "Process Injection"},
      {"T1055.001", "Process Injection: Dynamic-link Library Injection"},
      {"T1055.012", "Process Injection: Process Hollowing"},
      {"T1548", "Abuse Elevation Control Mechanism"},
      {"T1562.001", "Impair Defenses: Disable or Modify Tools"},
      {"T1027", "Obfuscated Files or Information"},
      {"T1027.002", "Obfuscated Files or Information: Software Packing"},
      {"T1140", "Deobfuscate/Decode Files or Information"},
      {"T1112", "Modify Registry"},
      {"T1218", "System Binary Proxy Execution"},
      {"T1218.011", "System Binary Proxy Execution: Rundll32"},
      {"T1218.010", "System Binary Proxy Execution: Regsvr32"},
      {"T1218.005", "System Binary Proxy Execution: Mshta"},
      {"T1497", "Virtualization/Sandbox Evasion"},
      {"T1620", "Reflective Code Loading"},
      // Credential Access
      {"T1555", "Credentials from Password Stores"},
      {"T1555.003", "Credentials from Password Stores: Credentials from Web Browsers"},
      {"T1003", "OS Credential Dumping"},
      {"T1056", "Input Capture"},
      {"T1056.001", "Input Capture: Keylogging"},
      {"T1539", "Steal Web Session Cookie"},
      // Discovery
      {"T1082", "System Information Discovery"},
      {"T1083", "File and Directory Discovery"},
      {"T1057", "Process Discovery"},
      {"T1018", "Remote System Discovery"},
      {"T1016", "System Network Configuration Discovery"},
      // Collection / C2 / Exfil
      {"T1005", "Data from Local System"},
      {"T1071", "Application Layer Protocol"},
      {"T1071.001", "Application Layer Protocol: Web Protocols"},
      {"T1219", "Remote Access Software"},
      {"T1113", "Screen Capture"},
      {"T1095", "Non-Application Layer Protocol"},
      {"T1105", "Ingress Tool Transfer"},
      {"T1573", "Encrypted Channel"},
      {"T1571", "Non-Standard Port"},
      {"T1041", "Exfiltration Over C2 Channel"},
      {"T1486", "Data Encrypted for Impact"},
      {"T1485", "Data Destruction"},
      {"T1490", "Inhibit System Recovery"},
      {"T1496", "Resource Hijacking"},
      {"T1561.002", "Disk Wipe: Disk Structure Wipe"},
      {"T1070.001", "Indicator Removal: Clear Windows Event Logs"},
      {"T1136.001", "Create Account: Local Account"},
      {"T1098", "Account Manipulation"},
      {"T1197", "BITS Jobs"},
  };
  const auto it = kCatalog.find(id);
  return it == kCatalog.end() ? std::string() : it->second;
}

std::string MitreTechniqueTactic(const std::string &id) {
  // Primary ATT&CK tactic per technique (the tactic AntiMal groups it under in
  // the report's kill-chain view). For techniques ATT&CK lists under several
  // tactics, the most behavior-relevant one is chosen. Covers every ID in the
  // name catalog above.
  static const std::unordered_map<std::string, std::string> kTactic = {
      {"T1059", "Execution"},        {"T1059.001", "Execution"},
      {"T1059.003", "Execution"},    {"T1059.005", "Execution"},
      {"T1059.007", "Execution"},    {"T1106", "Execution"},
      {"T1204", "Execution"},        {"T1204.002", "Execution"},
      {"T1047", "Execution"},        {"T1053", "Execution"},
      {"T1053.005", "Execution"},    {"T1569.002", "Execution"},
      {"T1547", "Persistence"},      {"T1547.001", "Persistence"},
      {"T1547.004", "Persistence"},  {"T1547.014", "Persistence"},
      {"T1543.003", "Persistence"},
      {"T1546", "Persistence"},      {"T1546.010", "Persistence"},
      {"T1546.012", "Persistence"},  {"T1546.015", "Persistence"},
      {"T1574", "Persistence"},      {"T1574.002", "Persistence"},
      {"T1136.001", "Persistence"},  {"T1098", "Persistence"},
      {"T1197", "Defense Evasion"},  {"T1548", "Privilege Escalation"},
      {"T1055", "Defense Evasion"},  {"T1055.001", "Defense Evasion"},
      {"T1055.012", "Defense Evasion"}, {"T1562.001", "Defense Evasion"},
      {"T1027", "Defense Evasion"},  {"T1027.002", "Defense Evasion"},
      {"T1140", "Defense Evasion"},  {"T1112", "Defense Evasion"},
      {"T1218", "Defense Evasion"},  {"T1218.011", "Defense Evasion"},
      {"T1218.010", "Defense Evasion"}, {"T1620", "Defense Evasion"},
      {"T1218.005", "Defense Evasion"}, {"T1497", "Defense Evasion"},
      {"T1070.001", "Defense Evasion"},
      {"T1555", "Credential Access"}, {"T1555.003", "Credential Access"},
      {"T1003", "Credential Access"}, {"T1056", "Credential Access"},
      {"T1056.001", "Credential Access"}, {"T1539", "Credential Access"},
      {"T1082", "Discovery"},        {"T1083", "Discovery"},
      {"T1057", "Discovery"},        {"T1018", "Discovery"},
      {"T1016", "Discovery"},        {"T1005", "Collection"},
      {"T1071", "Command and Control"}, {"T1071.001", "Command and Control"},
      {"T1219", "Command and Control"}, {"T1113", "Collection"},
      {"T1095", "Command and Control"}, {"T1105", "Command and Control"},
      {"T1573", "Command and Control"}, {"T1571", "Command and Control"},
      {"T1041", "Exfiltration"},     {"T1486", "Impact"},
      {"T1485", "Impact"},           {"T1490", "Impact"},
      {"T1496", "Impact"},           {"T1561.002", "Impact"},
  };
  auto it = kTactic.find(id);
  if (it != kTactic.end()) return it->second;
  // Sub-technique not explicitly listed -> fall back to the parent technique.
  const auto dot = id.find('.');
  if (dot != std::string::npos) {
    it = kTactic.find(id.substr(0, dot));
    if (it != kTactic.end()) return it->second;
  }
  return "Other";
}

} // namespace antimal
