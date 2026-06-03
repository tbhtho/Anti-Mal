// KdDrive.cs — drive kd.exe non-interactively to break into a RUNNING guest at
// timed intervals and dump state, so we can name a HANG (not a crash — a hang
// produces no auto-break, so we must send Ctrl+Break ourselves).
//
// kd is launched in its OWN process group (CREATE_NEW_PROCESS_GROUP) with stdin
// redirected; GenerateConsoleCtrlEvent(CTRL_BREAK, kdPid) then breaks ONLY kd
// into the target. After each break we write dump commands to kd's stdin, then
// "g" to resume (or "q" on the last break).
//
// Build:  csc /nologo /out:KdDrive.exe KdDrive.cs
// Usage:  KdDrive.exe "<connString>" "<logPath>" "<breakDelaysCsv>" "<dumpCmds>"
//   e.g.  KdDrive.exe "com:pipe,port=\\.\pipe\antimal-kd,resets=0,reconnect" \
//                     C:\AntiMalRuns\_kdrun.log "120,180,240" \
//                     ".reload /f; !running -t; !process 0 0; .time"
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

class KdDrive {
  [StructLayout(LayoutKind.Sequential)]
  struct STARTUPINFO {
    public int cb; public string lpReserved, lpDesktop, lpTitle;
    public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
    public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
  }
  [StructLayout(LayoutKind.Sequential)]
  struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }
  [StructLayout(LayoutKind.Sequential)]
  struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; public int bInheritHandle; }

  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool CreateProcess(string app, string cmd, IntPtr pa, IntPtr ta, bool inherit,
    uint flags, IntPtr env, string cwd, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool CreatePipe(out IntPtr rd, out IntPtr wr, ref SECURITY_ATTRIBUTES sa, int size);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool SetHandleInformation(IntPtr h, int mask, int flags);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool WriteFile(IntPtr h, byte[] buf, int n, out int wrote, IntPtr ov);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool ReadFile(IntPtr h, byte[] buf, int n, out int read, IntPtr ov);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool GenerateConsoleCtrlEvent(uint evt, uint group);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool AllocConsole();
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool FreeConsole();
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool SetConsoleCtrlHandler(IntPtr handler, bool add);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern uint WaitForSingleObject(IntPtr h, uint ms);

  const uint CREATE_NEW_PROCESS_GROUP = 0x00000200;
  const uint CTRL_BREAK_EVENT = 1;
  const int STARTF_USESTDHANDLES = 0x100;
  const int HANDLE_FLAG_INHERIT = 1;

  static StreamWriter log;
  static IntPtr kdStdinWr;
  static volatile bool connected = false;
  static void W(string s){ Console.WriteLine(s); if(log!=null){ log.WriteLine(s); log.Flush(); } }
  static void Send(string cmd){
    byte[] b = Encoding.ASCII.GetBytes(cmd + "\r\n");
    int wrote; WriteFile(kdStdinWr, b, b.Length, out wrote, IntPtr.Zero);
    W("[KdDrive] >>> " + cmd);
  }

  static int Main(string[] a){
    if(a.Length < 4){ Console.WriteLine("usage: KdDrive <conn> <log> <delaysCsv> <dumpCmds>"); return 2; }
    string conn=a[0], logPath=a[1], delaysCsv=a[2], dump=a[3];
    log = new StreamWriter(logPath, false);
    string kd = @"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe";

    // The background-task PowerShell context may have a non-interactive console
    // that swallows GenerateConsoleCtrlEvent. Detach from it and allocate a fresh
    // real console so the Ctrl+Break we send actually reaches kd. Ignore the
    // event in THIS process so our own break doesn't kill us.
    FreeConsole();
    AllocConsole();
    SetConsoleCtrlHandler(IntPtr.Zero, true); // this process ignores Ctrl+C

    var sa = new SECURITY_ATTRIBUTES();
    sa.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)); sa.bInheritHandle = 1;
    IntPtr inRd, inWr, outRd, outWr;
    CreatePipe(out inRd, out inWr, ref sa, 0);   SetHandleInformation(inWr, HANDLE_FLAG_INHERIT, 0);
    CreatePipe(out outRd, out outWr, ref sa, 0); SetHandleInformation(outRd, HANDLE_FLAG_INHERIT, 0);
    kdStdinWr = inWr;

    var si = new STARTUPINFO(); si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
    si.dwFlags = STARTF_USESTDHANDLES; si.hStdInput = inRd; si.hStdOutput = outWr; si.hStdError = outWr;
    // -c ".reload /f nt; g" : at the early KdInitSystem breakin, force-load the
    // ntkrnlmp symbols ONCE (cached to C:\symbols so later break dumps are fast)
    // then GO so the guest boots toward the hang; we break in later via Ctrl+Break.
    string cmd = "\"" + kd + "\" -k " + conn + " -c \".reload /f nt; g\"";
    PROCESS_INFORMATION pi;
    if(!CreateProcess(null, cmd, IntPtr.Zero, IntPtr.Zero, true, CREATE_NEW_PROCESS_GROUP, IntPtr.Zero, null, ref si, out pi)){
      W("CreateProcess failed: " + Marshal.GetLastWin32Error()); return 1;
    }
    CloseHandle(outWr); CloseHandle(inRd);
    W("[KdDrive] kd pid=" + pi.dwProcessId + " group started");

    // Reader thread: drain kd stdout -> log+console, and detect when the KD
    // session is actually established (kd auto-continues the target, so -c never
    // runs and we must break in ourselves — but only AFTER it's connected).
    var reader = new Thread(() => {
      byte[] buf = new byte[4096]; var tail = new StringBuilder();
      while(true){ int n; if(!ReadFile(outRd, buf, buf.Length, out n, IntPtr.Zero) || n==0) break;
        string s = Encoding.ASCII.GetString(buf,0,n); Console.Write(s); if(log!=null){ log.Write(s); log.Flush(); }
        tail.Append(s); if(tail.Length>2000) tail.Remove(0, tail.Length-2000);
        if(!connected && (tail.ToString().Contains("connection established") || tail.ToString().Contains("Connected to Windows"))) connected = true;
      }
    }); reader.IsBackground = true; reader.Start();

    // Wait for the KD session to establish before trying to break in.
    int waited = 0;
    while(!connected && waited < 240){ Thread.Sleep(1000); waited++; }
    if(!connected){ W("[KdDrive] target never connected within 240s"); }
    else { W("[KdDrive] connected after ~" + waited + "s; target is running (kd auto-continued). Breaking in on schedule."); }

    // Delays are measured FROM CONNECTION (let the boot progress, then break in
    // and dump). Symbols are pre-cached so the dump commands are fast.
    string[] delays = delaysCsv.Split(',');
    int prev = 0;
    for(int i=0;i<delays.Length && connected;i++){
      int t = int.Parse(delays[i].Trim());
      int waitMs = (t - prev) * 1000; prev = t;
      if(waitMs > 0) Thread.Sleep(waitMs);
      W("\n[KdDrive] === break #" + (i+1) + " at conn+" + t + "s ===");
      if(!GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, (uint)pi.dwProcessId))
        W("[KdDrive] GenerateConsoleCtrlEvent failed: " + Marshal.GetLastWin32Error());
      Thread.Sleep(6000); // let kd break in
      foreach(string c in dump.Split(';')) { Send(c.Trim()); Thread.Sleep(1500); }
      Thread.Sleep(6000); // let symbol-dependent commands finish
      Send(i == delays.Length-1 ? "q" : "g");
      Thread.Sleep(3000);
    }
    WaitForSingleObject(pi.hProcess, 30000);
    W("[KdDrive] done");
    log.Flush(); log.Close();
    return 0;
  }
}
