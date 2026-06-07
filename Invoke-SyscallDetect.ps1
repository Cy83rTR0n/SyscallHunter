#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory)][string]$SamplePath,
    [string]$OutputDir   = "C:\research",
    [int]$TimeoutSeconds = 30,
    [string]$ModulePath  = "",
    [switch]$KeepEtl
)

$SysmonGuid = "5770385f-c22a-43e0-bf4c-06f5698ffbd9"

function Write-Section($msg) { Write-Host "" ; Write-Host "=== $msg ===" -ForegroundColor Cyan }
function Write-Ok($msg)      { Write-Host "[+] $msg" -ForegroundColor Green  }
function Write-Warn($msg)    { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err($msg)     { Write-Host "[-] $msg" -ForegroundColor Red    }

function Get-SyscallAnomalies {
    param([string]$EtlPath)

    # Native NT processes that legitimately call ntdll directly
    $trustedNative = @(
        'csrss.exe','smss.exe','wininit.exe','lsass.exe',
        'services.exe','winlogon.exe','lsm.exe'
    )

    $results = @()
    $allEvents = Import-EtwFile $EtlPath | Where-Object { $_.Id -eq 10 -or $_.Id -eq 8 }

    foreach ($evt in $allEvents) {
        $sourceImage = $evt.Payload["SourceImage"]
        $sourceName  = ""
        if ($sourceImage) {
            $sourceName = [System.IO.Path]::GetFileName($sourceImage).ToLower()
        }
        if ($trustedNative -contains $sourceName) { continue }

        # --- Event 10: ProcessAccess - detect direct/indirect syscall via CallTrace ---
        if ($evt.Id -eq 10) {
            $trace = $evt.Payload["CallTrace"]
            if (-not $trace) { continue }

            $frames     = $trace -split '\|'
            $topFrame   = $frames[0]
            $frame1     = if ($frames.Length -gt 1) { $frames[1] } else { "" }
            $hasUnknown = $trace -match 'UNKNOWN'

            # DIRECT SYSCALL:
            #   The syscall instruction executed from inside the attacker's own
            #   memory, so the return address (top CallTrace frame) is not in
            #   ntdll at all.
            $isDirectSyscall = ($topFrame -notmatch 'ntdll\.dll') -and
                               ($topFrame -notmatch 'KERNELBASE\.dll|KERNEL32\.DLL')

            # INDIRECT SYSCALL:
            #   Attacker jumped to ntdll's own "syscall;ret" gadget, so ntdll
            #   IS the top frame -- but frame[1] is directly the attacker's
            #   code, bypassing the normal KERNELBASE -> KERNEL32 API path.
            #
            #   We check frame[1] only (not the full trace) because
            #   KERNEL32.DLL always appears at the BOTTOM of every Windows
            #   stack as BaseThreadInitThunk -- that is normal and must NOT
            #   be treated as evidence of a legitimate API call.
            $isIndirectSyscall = ($topFrame -match 'ntdll\.dll') -and
                                 ($frame1 -notmatch 'KERNELBASE\.dll|KERNEL32\.DLL') -and
                                 (-not $hasUnknown)

            if ($isDirectSyscall -or $isIndirectSyscall) {
                $tag = if ($isDirectSyscall) { "DIRECT_SYSCALL" } else { "INDIRECT_SYSCALL" }
                $results += [PSCustomObject]@{
                    TimeStamp     = $evt.TimeStamp
                    Detection     = $tag
                    EventId       = 10
                    SourceProcess = $sourceImage
                    TargetProcess = $evt.Payload["TargetImage"]
                    GrantedAccess = ("0x{0:X}" -f [long]$evt.Payload["GrantedAccess"])
                    TopFrame      = $topFrame
                    FullTrace     = $trace
                    Detail        = ""
                }
            }
        }

        # --- Event 8: CreateRemoteThread - cross-process thread injection ---
        if ($evt.Id -eq 8) {
            $startModule   = $evt.Payload["StartModule"]
            $startFunction = $evt.Payload["StartFunction"]
            $startAddress  = $evt.Payload["StartAddress"]
            $targetImage   = $evt.Payload["TargetImage"]

            # Flag all remote threads from non-trusted sources.
            # StartModule=UNKNOWN means shellcode injection (no PE backing).
            $results += [PSCustomObject]@{
                TimeStamp     = $evt.TimeStamp
                Detection     = "REMOTE_THREAD"
                EventId       = 8
                SourceProcess = $sourceImage
                TargetProcess = $targetImage
                GrantedAccess = "N/A"
                TopFrame      = $startAddress
                FullTrace     = "$startModule!$startFunction"
                Detail        = "StartModule=$startModule  StartFunction=$startFunction"
            }
        }
    }

    return $results
}

# =============================================================================
# PREFLIGHT
# =============================================================================
Write-Section "Preflight"

if (-not (Test-Path $SamplePath)) {
    Write-Err "Sample not found: $SamplePath"
    exit 1
}
Write-Ok "Sample: $SamplePath"

if (-not (Get-Module EtwInspector)) {
    if ($ModulePath -ne "" -and (Test-Path $ModulePath)) {
        Import-Module $ModulePath -Force
    } else {
        Import-Module EtwInspector -Force
    }
}
Write-Ok "EtwInspector loaded"

$svc = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne 'Running') {
    Write-Err "Sysmon64 is not running. Install with: sysmon64 -accepteula -i sysmon-config.xml"
    exit 1
}
Write-Ok "Sysmon64 running"

# =============================================================================
# OUTPUT PATHS
# =============================================================================
$ts         = Get-Date -Format "yyyyMMdd_HHmmss"
$sampleName = [System.IO.Path]::GetFileNameWithoutExtension($SamplePath)
$runDir     = Join-Path $OutputDir ($sampleName + "_" + $ts)
New-Item -ItemType Directory -Path $runDir -Force | Out-Null

$etlPath    = Join-Path $runDir "capture.etl"
$snapBefore = Join-Path $runDir "snapshot_before.ndjson"
$snapAfter  = Join-Path $runDir "snapshot_after.ndjson"
$diffPath   = Join-Path $runDir "provider_diff.json"
$reportPath = Join-Path $runDir "report.json"
$traceName  = "SyscallDetect_" + $ts

Write-Ok "Output: $runDir"

# =============================================================================
# ETW PROVIDER SNAPSHOT -- BEFORE
# =============================================================================
Write-Section "Snapshot Before"
Export-EtwSnapshot $snapBefore -SkipTraceLogging
Write-Ok "Saved: $snapBefore"

# =============================================================================
# START ETW CAPTURE (Sysmon provider)
# =============================================================================
Write-Section "Start ETW Capture"
$session = Start-EtwCapture -ProviderGuids $SysmonGuid -TraceName $traceName -OutputFilePath $etlPath
Write-Ok "Session started: $traceName"

# =============================================================================
# RUN SAMPLE
# =============================================================================
Write-Section "Execute Sample"
Write-Warn "Launching: $SamplePath"
Write-Warn "Timeout  : $TimeoutSeconds seconds"

$sampleProc = $null
try {
    $sampleProc = Start-Process -FilePath $SamplePath -PassThru
    Write-Ok "PID: $($sampleProc.Id)"
    $exited = $sampleProc.WaitForExit($TimeoutSeconds * 1000)
    if ($exited) {
        Write-Ok "Sample exited (code $($sampleProc.ExitCode))"
    } else {
        Write-Warn "Timeout reached - force killing PID $($sampleProc.Id)"
        Stop-Process -Id $sampleProc.Id -Force -ErrorAction SilentlyContinue
    }
} catch {
    Write-Err "Launch failed: $_"
}

# Extra wait so Sysmon flushes its internal event buffer to the ETL file
Start-Sleep -Seconds 5

# =============================================================================
# STOP CAPTURE
# =============================================================================
Write-Section "Stop Capture"
$session | Stop-EtwCapture
Write-Ok "Capture stopped"

# =============================================================================
# ETW PROVIDER SNAPSHOT -- AFTER + TAMPER DIFF
# =============================================================================
Write-Section "Snapshot After and ETW Tamper Check"
Export-EtwSnapshot $snapAfter -SkipTraceLogging
Write-Ok "Saved: $snapAfter"

$diff     = Compare-EtwSnapshot $snapBefore $snapAfter
$nAdded   = @($diff.ProvidersAdded).Count
$nRemoved = @($diff.ProvidersRemoved).Count
$nChanged = @($diff.ProvidersChanged).Count

if ($nAdded -eq 0 -and $nRemoved -eq 0 -and $nChanged -eq 0) {
    Write-Ok "No ETW provider changes -- no tampering detected"
} else {
    Write-Warn "ETW provider changes detected!  Added=$nAdded  Removed=$nRemoved  Changed=$nChanged"
    $diff | ConvertTo-Json -Depth 20 | Set-Content $diffPath
    Write-Warn "Diff saved: $diffPath"
}

# =============================================================================
# SYSCALL ANOMALY ANALYSIS
# =============================================================================
Write-Section "Syscall Anomaly Analysis"
$anomalies = Get-SyscallAnomalies -EtlPath $etlPath

if ($anomalies.Count -eq 0) {
    Write-Ok "No direct/indirect syscall anomalies detected"
} else {
    Write-Warn "$($anomalies.Count) anomaly(s) found!"
    foreach ($a in $anomalies) {
        Write-Host ""
        Write-Host "  Detection     : " -NoNewline
        Write-Host $a.Detection -ForegroundColor Red
        Write-Host "  EventId       : $($a.EventId)"
        Write-Host "  SourceProcess : $($a.SourceProcess)"
        Write-Host "  TargetProcess : $($a.TargetProcess)"
        if ($a.EventId -eq 10) {
            Write-Host "  GrantedAccess : $($a.GrantedAccess)"
            Write-Host "  CallTrace:"
            foreach ($frame in ($a.FullTrace -split '\|')) {
                Write-Host "    $frame"
            }
        } else {
            Write-Host "  $($a.Detail)"
        }
    }
}

# =============================================================================
# SAVE JSON REPORT
# =============================================================================
Write-Section "Report"
$report = [PSCustomObject]@{
    Sample       = $SamplePath
    Timestamp    = $ts
    ETWTampering = [PSCustomObject]@{ Added=$nAdded; Removed=$nRemoved; Changed=$nChanged }
    AnomalyCount = $anomalies.Count
    Anomalies    = $anomalies
}
$report | ConvertTo-Json -Depth 20 | Set-Content $reportPath
Write-Ok "Report: $reportPath"

if (-not $KeepEtl) {
    Remove-Item $etlPath -Force -ErrorAction SilentlyContinue
    Write-Ok "ETL deleted (use -KeepEtl to retain it)"
}

Write-Section "Done"
Write-Host "Results in: $runDir"
