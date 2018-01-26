REM - Clean up an existing or past 'test session'
taskkill /F /IM "ida.exe"
taskkill /F /IM "ida64.exe"
timeout 1

REM - Delete the old plugin bits
del /F /Q "%APPDATA%\Hex-Rays\IDA Pro\plugins\*bbtrace_plugin.py"
rmdir     "%APPDATA%\Hex-Rays\IDA Pro\plugins\bbtrace" /s /q

REM - Copy over the new plugin bits
xcopy /s/y "plugin\*" "%APPDATA%\Hex-Rays\IDA Pro\plugins\"

REM - Launch a new IDA session
start "" "C:\Program Files\IDA 7.0\ida.exe"
