' AntiMal launcher - runs the GUI menu with NO console window.
' Double-click this file.
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
ps1 = scriptDir & "\AntiMal.ps1"
If Not fso.FileExists(ps1) Then
  MsgBox "AntiMal.ps1 not found next to this launcher.", 16, "AntiMal"
  WScript.Quit 1
End If
shell.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & ps1 & """", 0, False
