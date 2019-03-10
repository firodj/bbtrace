@echo off
setlocal

set CONFIG=RelWithDebInfo

IF "%1"=="" (
  (echo Please supply a client, eg. `bbtrace`)
  GOTO:stop
)

set TOOL_PATH=bin\%CONFIG%\%1.exe
IF exist "%TOOL_PATH%" (
  echo %TOOL_PATH% %2 %3 %4 %5 %6 %7 %8 %9
  start "" "%TOOL_PATH%" %2 %3 %4 %5 %6 %7 %8 %9
  GOTO:stop
)

IF "%2"=="" (
  (echo Please use `--` then application exe)
  GOTO:stop
)

SET LOCAL=%~dp0
SET LOCAL=%LOCAL:~0,-1%

Set filename=%3

if not exist "%filename%" (
	(echo No application %filename%)
	GOTO:stop
)

For %%A in ("%filename%") do (
    Set Folder=%%~dpA
    Set Name=%%~nxA
)

SET Options=-memtrace
SET ARGS=-c %LOCAL%\bin\%CONFIG%\%1.dll %Options% -- %Name% %4 %5 %6 %7 %8 %9

:run

del %LOCAL%\bin\%CONFIG%\%1.dll.*.EXE.*

pushd %Folder%

echo %cd%
echo %DYNAMORIO_HOME%\bin32\drrun.exe -syntax_intel %ARGS%

%DYNAMORIO_HOME%\bin32\drrun.exe -syntax_intel %ARGS%
popd

:stop
endlocal