@echo off
rem Generate MD5.txt for all files in this directory and its subdirectories.
rem Excluded (top-level only): hashkit executables, gen-md5/verify-md5 scripts, MD5.txt itself.
rem Requires hashkit.exe in the same directory.
rem Exit code: 0 ok, 2 error
chcp 65001 >nul
cd /d "%~dp0"

if not exist hashkit.exe (
    echo ERROR: hashkit.exe not found in the current directory.
    set RC=2
    goto :end
)

rem Work files go to the system temp dir so they are not listed.
set TMPA=%TEMP%\hashkit_md5_%RANDOM%a.tmp
set TMPB=%TEMP%\hashkit_md5_%RANDOM%b.tmp
hashkit.exe hash . -r -a md5 > "%TMPA%"
if errorlevel 1 (
    set RC=2
    goto :cleanup
)

rem hashkit writes LF-only lines, which findstr /e cannot match at end of line.
rem find /v "" rewrites them with CRLF.
find /v "" < "%TMPA%" > "%TMPB%"

rem Each line is "<md5>  <path>"; matching the two spaces plus the end of line
rem excludes only top-level files with exactly these names.
findstr /v /l /e /i /c:"  hashkit.exe" /c:"  hashkit-linux-amd64" /c:"  hashkit" /c:"  gen-md5.sh" /c:"  gen-md5.bat" /c:"  verify-md5.sh" /c:"  verify-md5.bat" /c:"  MD5.txt" "%TMPB%" > MD5.txt
if errorlevel 1 (
    del MD5.txt >nul 2>&1
    echo ERROR: no files left to hash after excluding tool files.
    set RC=2
    goto :cleanup
)

for /f %%n in ('find /c /v "" ^< MD5.txt') do echo Written %%n entries to MD5.txt
set RC=0

:cleanup
del "%TMPA%" "%TMPB%" >nul 2>&1

:end
rem Pause only when started by double-click, so the window does not vanish.
echo %cmdcmdline% | find /i "/c" >nul && pause
exit /b %RC%
