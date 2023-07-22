@echo off

set SIGN_TOOL=".\.SignTool.exe"
set PFX_FILE=".\private.pfx"
set EXE_FILE=".\hello.exe"

%SIGN_TOOL% sign /fd SHA256 /f %PFX_FILE% %EXE_FILE%

pause
if errorlevel 1 (
    echo Failed to sign the executable.
    exit /b 1
) else (
    echo Executable signed successfully.
    exit /b 0
)

