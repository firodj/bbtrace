@echo off

set CONFIG=RelWithDebInfo

IF "%1"=="" (
  (echo Please supply a client, eg. `bbtrace`)
  GOTO:eof
)

IF "%1"=="parselog" (
  echo bin\%CONFIG%\parselog.exe %2 %3 %4 %5 %6 %7 %8 %9
  start bin\%CONFIG%\parselog.exe %2 %3 %4 %5 %6 %7 %8 %9
  GOTO :eof
)

IF "%2"=="" (
  (echo Please use `--` then application exe)
  GOTO:eof
)

SET LOCAL=%~dp0
SET LOCAL=%LOCAL:~0,-1%

Set filename=%3

if not exist "%filename%" (
	(echo No application %filename%)
	GOTO:eof
)

For %%A in ("%filename%") do (
    Set Folder=%%~dpA
    Set Name=%%~nxA
)

rem SET Options=-memtrace
SET ARGS=-c %LOCAL%\bin\%CONFIG%\%1.dll %Options% -- %Name% %4 %5 %6 %7 %8 %9

:run

del %LOCAL%\bin\%CONFIG%\%1.dll.*.EXE.*

pushd %Folder%

echo %cd%
echo %DYNAMORIO_HOME%\bin32\drrun.exe -syntax_intel %ARGS%

%DYNAMORIO_HOME%\bin32\drrun.exe -syntax_intel %ARGS%
popd
