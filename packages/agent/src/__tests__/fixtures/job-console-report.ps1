$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
public static class JobConsoleReport {
    [StructLayout(LayoutKind.Sequential)] public struct Coord { public short X; public short Y; }
    [StructLayout(LayoutKind.Sequential)] public struct Rect { public short Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] public struct Info {
        public Coord Size, Cursor; public ushort Attributes; public Rect Window; public Coord Maximum;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateFile(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetConsoleScreenBufferInfo(IntPtr handle, out Info info);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool ReadConsoleOutputCharacter(IntPtr handle, StringBuilder text, uint length, Coord start, out uint read);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern uint GetConsoleTitle(StringBuilder title, uint size);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    public static string Title() {
        var text = new StringBuilder(1024);
        GetConsoleTitle(text, (uint)text.Capacity);
        return text.ToString();
    }
    public static string Screen() {
        // stdout points at output.log. Open the actual shared console explicitly.
        var handle = CreateFile("CONOUT$", 0x80000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (handle == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            Info info;
            if (!GetConsoleScreenBufferInfo(handle, out info)) throw new Win32Exception(Marshal.GetLastWin32Error());
            int length = info.Size.X * info.Size.Y;
            var text = new StringBuilder(length);
            uint read;
            if (!ReadConsoleOutputCharacter(handle, text, (uint)length, new Coord(), out read))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return text.ToString();
        } finally { CloseHandle(handle); }
    }
}
'@
@{ title = [JobConsoleReport]::Title(); screen = [JobConsoleReport]::Screen() } |
    ConvertTo-Json -Compress | Set-Content -LiteralPath $env:AIC_TEST_CONSOLE_REPORT -Encoding UTF8
Write-Output 'payload'
exit 7
