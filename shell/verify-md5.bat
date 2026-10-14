@echo off
rem Verify all files in this directory and its subdirectories against MD5.txt.
rem Requires hashkit.exe and MD5.txt in the same directory.
rem Exit code: 0 all match, 1 mismatch or unreadable, 2 error
chcp 65001 >nul
cd /d "%~dp0"

if not exist hashkit.exe (
    echo ERROR: hashkit.exe not found in the current directory.
    set RC=2
    goto :end
)
if not exist MD5.txt (
    echo ERROR: MD5.txt not found. Run gen-md5.bat first.
    set RC=2
    goto :end
)

hashkit.exe verify MD5.txt -C . -a md5
set RC=%ERRORLEVEL%

:end
rem Pause only when started by double-click, so the window does not vanish.
echo %cmdcmdline% | find /i "/c" >nul && pause
exit /b %RC%
