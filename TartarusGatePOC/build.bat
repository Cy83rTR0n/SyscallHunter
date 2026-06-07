@echo off
setlocal enabledelayedexpansion

:: build.bat -- Compile TartarusGate.exe  (MSVC x64 + MASM ml64)
::
:: 1. If already in an "x64 Native Tools" developer prompt, builds immediately.
:: 2. Otherwise uses vswhere.exe (ships with VS 2017+) to locate vcvars64.bat.
:: 3. Falls back with manual instructions if neither works.

:: ── Already in a developer prompt? ───────────────────────────────────────
where ml64.exe >nul 2>&1
if not errorlevel 1 (
    echo [*] ml64 found in PATH - using current developer environment
    goto :build
)

:: ── Use vswhere.exe to find the VS install path ───────────────────────────
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [-] vswhere.exe not found at:
    echo     %VSWHERE%
    goto :manual
)

set "VS_PATH="
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -property installationPath`) do (
    set "VS_PATH=%%i"
)

if not defined VS_PATH (
    echo [-] vswhere found no Visual Studio installation
    goto :manual
)

set "VCVARS=!VS_PATH!\VC\Auxiliary\Build\vcvars64.bat"
if not exist "!VCVARS!" (
    echo [-] vcvars64.bat not found at:
    echo     !VCVARS!
    goto :manual
)

echo [*] Initialising MSVC x64 environment from:
echo     !VCVARS!
call "!VCVARS!" > nul 2>&1
if errorlevel 1 ( echo [-] vcvars64 initialisation failed & exit /b 1 )
goto :build

:manual
echo.
echo  Open an "x64 Native Tools Command Prompt for VS 20xx" and run:
echo.
echo    cd /d "%~dp0"
echo    ml64  /nologo /c /Fo syscalls.obj     syscalls.asm
echo    cl    /nologo /c /W3 /Fo tartarus_gate.obj  tartarus_gate.c
echo    link  /nologo /OUT:TartarusGate.exe /SUBSYSTEM:CONSOLE ^
echo          tartarus_gate.obj syscalls.obj kernel32.lib advapi32.lib
echo.
exit /b 1

:: ── Build ─────────────────────────────────────────────────────────────────
:build

echo.
echo [*] Assembling syscalls.asm ...
ml64 /nologo /c /Fo syscalls.obj syscalls.asm
if errorlevel 1 ( echo [-] ml64 failed & exit /b 1 )
echo [+] syscalls.obj

echo [*] Compiling tartarus_gate.c ...
cl /nologo /c /W3 /Fo tartarus_gate.obj tartarus_gate.c
if errorlevel 1 ( echo [-] cl failed & exit /b 1 )
echo [+] tartarus_gate.obj

echo [*] Linking TartarusGate.exe ...
link /nologo /OUT:TartarusGate.exe /SUBSYSTEM:CONSOLE ^
    tartarus_gate.obj syscalls.obj ^
    kernel32.lib advapi32.lib
if errorlevel 1 ( echo [-] link failed & exit /b 1 )

echo.
echo [+] Build successful: TartarusGate.exe
echo.
echo     Standalone test:
echo       TartarusGate.exe
echo.
echo     Detection pipeline:
echo       powershell -ExecutionPolicy Bypass ^
echo         ..\Invoke-SyscallDetect.ps1 -SamplePath .\TartarusGate.exe

endlocal
