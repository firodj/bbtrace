@echo off
setlocal enabledelayedexpansion

echo Clean up an existing or past 'test session'
taskkill /F /IM "ida.exe"
taskkill /F /IM "ida64.exe"
timeout 1

echo Delete the old plugin bits
del /F /Q "%APPDATA%\Hex-Rays\IDA Pro\plugins\*bbtrace_plugin.py"
rmdir     "%APPDATA%\Hex-Rays\IDA Pro\plugins\bbtrace" /s /q

echo Copy over the new plugin bits
xcopy /s/y "plugin\*" "%APPDATA%\Hex-Rays\IDA Pro\plugins\"

echo Launch a new IDA session
set IDA_PATH=C:\Program Files\IDA 7.0

if not exist "%IDA_PATH%" (
  set IDA_PATH=C:\Program Files\IDA Freeware 7.0
  echo !IDA_PATH!
  if exist "!IDA_PATH!" (
    echo Sorry, unfortunately it doesn't work on the freeware version :(
  )
  goto :eof
)

echo %IDA_PATH%
start "" "%IDA_PATH%\ida"
