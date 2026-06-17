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
      {"T1543.003", "Create or Modify System Process: Windows Service"},
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
      {"T1218.005", "System Binary Proxy Execution: Mshta"},
      {"T1497", "Virtualization/Sandbox Evasion"},
      // Credential Access
      {"T1555", "Credentials from Password Stores"},
      {"T1555.003", "Credentials from Password Stores: Credentials from Web Browsers"},
      {"T1003", "OS Credential Dumping"},
      {"T1056.001", "Input Capture: Keylogging"},
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
      {"T1095", "Non-Application Layer Protocol"},
      {"T1105", "Ingress Tool Transfer"},
      {"T1573", "Encrypted Channel"},
      {"T1571", "Non-Standard Port"},
      {"T1041", "Exfiltration Over C2 Channel"},
      {"T1486", "Data Encrypted for Impact"},
  };
  const auto it = kCatalog.find(id);
  return it == kCatalog.end() ? std::string() : it->second;
}

} // namespace antimal
