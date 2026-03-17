@echo off

REM Check if p.exe is running
tasklist /fi "IMAGENAME eq p.exe" 2>nul | find /i "p.exe" >nul
if %errorlevel%==0 (
    echo p.exe running - killing...
    taskkill /f /im p.exe
) else (
    echo p.exe not running
)

REM Check if r.bat window is running
tasklist /fi "WINDOWTITLE eq r.bat" 2>nul | find /i "cmd.exe" >nul
if %errorlevel%==0 (
    echo r.bat running - killing...
    taskkill /f /im cmd.exe /fi "WINDOWTITLE eq r.bat"
) else (
    echo r.bat not running
)

REM Delete temp files
if exist %TEMP%\r.bat (
    echo Deleting %TEMP%\r.bat
    del /f /q %TEMP%\r.bat
)
if exist %TEMP%\p.exe (
    echo Deleting %TEMP%\p.exe
    del /f /q %TEMP%\p.exe
)

echo Cleanup complete.
