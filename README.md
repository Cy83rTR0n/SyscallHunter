# SyscallHunter

> **Fork of [ETWInspector](https://github.com/jonny-jhnson/ETWInspector)** — extended with an automated direct/indirect syscall detection pipeline built on ETW + Sysmon.

ETWInspector is a comprehensive Event Tracing for Windows (ETW) toolkit for enumerating providers and capturing traces. This fork adds three new cmdlets and a full research pipeline for detecting syscall-based evasion techniques (Hell's Gate, Tartarus' Gate, direct syscalls) commonly used by malware and red-team tooling.

---

## What's new in this fork

| Addition | Type | Purpose |
|---|---|---|
| `Import-EtwFile` | Cmdlet | Parse an `.etl` file into PowerShell objects |
| `Get-EtwKeywordMask` | Cmdlet | Build a keyword bitmask from human-readable keyword names |
| `Receive-EtwCapture` | Cmdlet | Stream live ETW events from a running capture session |
| `Invoke-SyscallDetect.ps1` | Script | End-to-end automated detection pipeline |
| `TartarusGatePOC/` | C + MASM | Research POC to validate the detection pipeline |
| `sysmon-config.xml` | Config | Sysmon rules tuned for ProcessAccess + CreateRemoteThread |

---

## How the detection works

Modern malware bypasses user-mode EDR hooks on `ntdll.dll` using two techniques:

**Direct syscall** — the malware embeds the `syscall` instruction in its own code alongside the raw System Service Number (SSN). No ntdll is involved, so any inline hooks placed there are skipped entirely.

**Indirect syscall** — the malware resolves ntdll's own `syscall;ret` gadget address and jumps to it. The kernel sees the return address as inside ntdll, making the call look legitimate at first glance.

Both techniques are detected by analysing the **Sysmon Event 10 `CallTrace`** field, which Sysmon captures via kernel-mode stack walking — a layer that cannot be bypassed from user mode.

```
Legitimate API call:
  ntdll.dll        <- syscall
  KERNELBASE.dll   <- OpenProcess() implementation  <- frame[1]
  KERNEL32.DLL     <- OpenProcess() stub
  caller.exe

Indirect syscall (detected):
  ntdll.dll        <- gadget jumped to by attacker  <- frame[0]: ntdll
  attacker.exe     <- ZwOpenProcess call site        <- frame[1]: NOT KERNELBASE
  attacker.exe     <- main()
  KERNEL32.DLL     <- BaseThreadInitThunk (normal thread epilogue)
  ntdll.dll        <- RtlUserThreadStart

Direct syscall (detected):
  attacker.exe     <- syscall ran here               <- frame[0]: NOT ntdll
  attacker.exe
  ...
```

The key signal: **frame\[1\] immediately after ntdll is the attacker's own module**, bypassing the normal `KERNELBASE → KERNEL32` API chain. `KERNEL32.DLL` at the *bottom* of the trace is the standard thread startup epilogue (`BaseThreadInitThunk`) present in every Windows stack and is intentionally ignored.

---

## Prerequisites

- Windows 10/11 x64
- PowerShell 5.1 (run as Administrator)
- [Sysmon v13+](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) installed with the provided config
- EtwInspector module built or installed (see below)

### Install Sysmon with the detection config

```powershell
# First install
sysmon64 -accepteula -i TartarusGatePOC\sysmon-config.xml

# Update existing install
sysmon64 -c TartarusGatePOC\sysmon-config.xml
```

---

## Installation

### Option A — PowerShell Gallery (original cmdlets only)

```powershell
Install-Module EtwInspector
Import-Module EtwInspector
```

### Option B — Build from source (includes new cmdlets)

```powershell
# Requires .NET SDK or Visual Studio
dotnet build EtwInspector\EtwInspector.sln -c Release

# Copy output into the module
Copy-Item EtwInspector\bin\Release\EtwInspector.dll `
          EtwInspector\EtwInspectorModule\bin\EtwInspector.dll -Force

# Load the module
Import-Module .\EtwInspector\EtwInspectorModule\EtwInspector.psd1 -Force
```

### Verify all cmdlets are available

```
PS > Get-Command -Module EtwInspector

CommandType  Name                      Version
-----------  ----                      -------
Cmdlet       Compare-EtwSnapshot       1.3.0
Cmdlet       Export-EtwSnapshot        1.3.0
Cmdlet       Get-EtwKeywordMask        1.3.0
Cmdlet       Get-EtwProviders          1.3.0
Cmdlet       Get-EtwSecurityDescriptor 1.3.0
Cmdlet       Get-EtwTraceSessions      1.3.0
Cmdlet       Import-EtwFile            1.3.0
Cmdlet       Receive-EtwCapture        1.3.0
Cmdlet       Start-EtwCapture          1.3.0
Cmdlet       Stop-EtwCapture           1.3.0
```

---

## Detection pipeline — Invoke-SyscallDetect.ps1

The script automates the full research workflow:

```
ETW provider snapshot (before)
        ↓
Start Sysmon ETW capture
        ↓
Execute sample under test
        ↓
Stop capture (5 s flush buffer)
        ↓
ETW provider snapshot (after) + tamper diff
        ↓
Parse ETL → analyse CallTrace → flag anomalies
        ↓
JSON report
```

### Usage

```powershell
# Basic run
.\Invoke-SyscallDetect.ps1 -SamplePath .\malware.exe

# Keep the raw ETL for further analysis
.\Invoke-SyscallDetect.ps1 -SamplePath .\malware.exe -KeepEtl

# Custom output dir and timeout
.\Invoke-SyscallDetect.ps1 -SamplePath .\malware.exe -OutputDir C:\research -TimeoutSeconds 60

# Point at a specific module build
.\Invoke-SyscallDetect.ps1 -SamplePath .\malware.exe `
    -ModulePath .\EtwInspector\EtwInspectorModule\EtwInspector.psd1
```

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `-SamplePath` | *(required)* | Path to the binary under test |
| `-OutputDir` | `C:\research` | Root directory for run output |
| `-TimeoutSeconds` | `30` | Max time to wait for sample to exit |
| `-ModulePath` | *(auto)* | Path to `EtwInspector.psd1` if not on PSModulePath |
| `-KeepEtl` | off | Retain the raw `.etl` capture file |

### Example output

```
=== Preflight ===
[+] Sample: .\Tartarus_Gate_POC.exe
[+] EtwInspector loaded
[+] Sysmon64 running
[+] Output: C:\research\Tartarus_Gate_POC_20260607_123918

=== Syscall Anomaly Analysis ===
[!] 1 anomaly(s) found!

  Detection     : INDIRECT_SYSCALL
  EventId       : 10
  SourceProcess : C:\...\Tartarus_Gate_POC.exe
  TargetProcess : C:\Windows\System32\RuntimeBroker.exe
  GrantedAccess : 0x1FFFFF
  CallTrace:
    C:\Windows\SYSTEM32\ntdll.dll+9cd74
    C:\...\Tartarus_Gate_POC.exe+15f6
    C:\...\Tartarus_Gate_POC.exe+1b80
    C:\Windows\System32\KERNEL32.DLL+17034
    C:\Windows\SYSTEM32\ntdll.dll+52651
```

### Output files

Each run creates a timestamped folder under `OutputDir`:

```
C:\research\sample_20260607_123918\
    capture.etl              # raw Sysmon ETL (only with -KeepEtl)
    snapshot_before.ndjson   # ETW provider state before execution
    snapshot_after.ndjson    # ETW provider state after execution
    provider_diff.json       # diff (only written if changes detected)
    report.json              # full structured JSON report
```

---

## New cmdlets

### Import-EtwFile

Parses a `.etl` file and returns events as PowerShell objects.

```powershell
$events = Import-EtwFile C:\research\capture.etl

# Inspect Sysmon ProcessAccess events
$events | Where-Object Id -eq 10 | Select-Object TimeStamp, Payload

# Group by event ID
$events | Group-Object Id | Sort-Object Count -Descending
```

Each returned object has:
- `TimeStamp` — event timestamp
- `Id` — ETW event ID (e.g. 10 for Sysmon ProcessAccess)
- `ProviderName` — ETW provider name
- `Payload` — hashtable of all event fields (e.g. `CallTrace`, `SourceImage`)

### Get-EtwKeywordMask

Resolves human-readable keyword names to their bitmask value for use with `Start-EtwCapture -Keywords`.

```powershell
# List all keywords for a provider
Get-EtwKeywordMask -ProviderGuid "f4e1897c-bb5d-5668-f1d8-040f4d8dd344" -ListKeywords

# Build a mask for specific keywords
$mask = Get-EtwKeywordMask -ProviderGuid "f4e1897c-bb5d-5668-f1d8-040f4d8dd344" `
    -Keywords "KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE","KERNEL_THREATINT_KEYWORD_WRITEVM_REMOTE"

Start-EtwCapture -ProviderGuids "f4e1897c-bb5d-5668-f1d8-040f4d8dd344" `
    -Keywords $mask -OutputFilePath C:\research\msti.etl
```

### Receive-EtwCapture

Streams live events from a running capture session into the pipeline.

```powershell
$session = Start-EtwCapture -ProviderGuids "5770385f-c22a-43e0-bf4c-06f5698ffbd9" `
    -TraceName "LiveCapture" -OutputFilePath C:\research\live.etl

# Stream events in real time (Ctrl+C to stop)
$session | Receive-EtwCapture | Where-Object Id -eq 10 | ForEach-Object {
    Write-Host "$($_.Payload['SourceImage']) -> $($_.Payload['TargetImage'])"
}
```

---

## TartarusGatePOC — research validation sample

A purpose-built C + MASM x64 binary that demonstrates indirect syscall injection and validates the detection pipeline end-to-end.

### Technique

- **Hell's Gate** — reads SSN directly from ntdll stub bytes (`4C 8B D1 B8 [SSN]`)
- **Tartarus' Gate** — if the stub is hooked, recovers the SSN from a clean neighbouring stub via ordinal arithmetic
- **Indirect syscall** — jumps to ntdll's own `syscall;ret` gadget so the return address seen by the kernel is inside ntdll

### Syscall stubs (syscalls.asm)

The x64 MASM stubs read SSN values from globals that are populated at runtime by the resolver:

```asm
ZwOpenProcess PROC
    mov  r10, rcx                           ; Windows syscall ABI
    mov  eax, dword ptr [g_ssnNtOpenProcess] ; SSN set at runtime
    jmp  qword ptr [g_pGadget]              ; indirect: lands in ntdll
ZwOpenProcess ENDP
```

### Injection flow

```
1. Enumerate ntdll EAT -> resolve SSN for each syscall
2. Find ntdll's "syscall;ret" gadget -> set g_pGadget
3. ZwOpenProcess(RuntimeBroker.exe, PROCESS_ALL_ACCESS)  -> Sysmon Event 10
4. ZwAllocateVirtualMemory -> allocate "calc\0" in target
5. ZwWriteVirtualMemory   -> write "calc\0"
6. ZwCreateThreadEx at WinExec("calc", 1)               -> Sysmon Event 8
```

### Build

Open the `TartarusGatePOC` folder as a Visual Studio project:

1. **File → Open → Folder** → select `TartarusGatePOC\`
2. Right-click project → **Build Dependencies → Build Customizations** → check `masm`
3. Right-click `syscalls.asm` → Properties → **Item Type: Microsoft Macro Assembler**
4. Set platform to **x64** → **Build → Build Solution**

---

## Original ETWInspector cmdlets

All original cmdlets are unchanged. Full documentation below.

### Get-EtwProviders

Enumerates Manifest, MOF, and TraceLogging ETW providers.

```powershell
# Find providers by name
$p = Get-EtwProviders -ProviderName "Threat-Intelligence"
$p.RegisteredProviders | Select-Object providerName, providerGuid

# Find providers with a specific keyword in any property
Get-EtwProviders -PropertyString "AllocVm"

# Enumerate TraceLogging providers from a specific binary
Get-EtwProviders -ProviderType TraceLogging -FilePath C:\Windows\System32\kerberos.dll
```

> **TraceLogging caveat:** Events are not individually bound to a provider in the binary metadata — provider and event records appear in separate arrays with no cross-reference. Both are returned as flat lists. For static binding, use the [TLGMapper](https://github.com/AsuNa-jp/TLGMapper) IDA plugin.

### Get-EtwTraceSessions

Queries active trace sessions locally or remotely.

```powershell
Get-EtwTraceSessions
Get-EtwTraceSessions -ComputerName remotehost
```

### Export-EtwSnapshot / Compare-EtwSnapshot

Snapshot provider state and diff across machines or Windows versions.

```powershell
Export-EtwSnapshot C:\Snapshots\baseline.ndjson
Export-EtwSnapshot C:\Snapshots\baseline.ndjson -SkipTraceLogging   # faster, no TraceLogging scan

$diff = Compare-EtwSnapshot C:\Snapshots\before.ndjson C:\Snapshots\after.ndjson
$diff | ConvertTo-Json -Depth 20 | Set-Content C:\Snapshots\diff.json

# Side-by-side in VS Code
code --diff C:\Snapshots\before.ndjson C:\Snapshots\after.ndjson
```

### Start-EtwCapture / Stop-EtwCapture

```powershell
$session = Start-EtwCapture -ProviderGuids "5770385f-c22a-43e0-bf4c-06f5698ffbd9" `
    -TraceName "MySysmonCapture" -OutputFilePath C:\research\capture.etl

# ... run sample ...

$session | Stop-EtwCapture
```

---

## Resources

- [ETWInspector (original)](https://github.com/jonny-jhnson/ETWInspector) — base project
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) — kernel-mode event source
- [Microsoft.Diagnostics.Tracing.TraceEvent](https://www.nuget.org/packages/Microsoft.Diagnostics.Tracing.TraceEvent) — ETL parsing library
- [TLGMapper](https://github.com/AsuNa-jp/TLGMapper) — TraceLogging static analysis
- [Fody / Costura.Fody](https://github.com/Fody/Costura) — single-DLL embedding

---

## Disclaimer

The `TartarusGatePOC` is provided **for defensive security research only** — to validate detection pipelines in isolated, controlled lab environments. Only run it on systems you own. The techniques demonstrated (Hell's Gate, Tartarus' Gate, indirect syscalls) are documented in public security research; this implementation exists to give defenders a known-good sample to test their detection stack against.

---

## Credits

Original ETWInspector developed by [jonny-jhnson](https://github.com/jonny-jhnson).  
Thanks to Olaf Hartong and Matt Graeber for testing feedback on the original project.
