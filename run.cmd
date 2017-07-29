@echo off

IF "%1"=="" (
  (echo Please supply a client, eg. `bbtrace`)
  GOTO:eof
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

SET ARGS=-c %LOCAL%\build\RelWithDebInfo\%1.dll -- %Name% %4 %5 %6 %7 %8 %9

:run

pushd %Folder%

echo %cd%
echo %DYNAMORIO_HOME%\bin32\drrun.exe -syntax_intel %ARGS%

%DYNAMORIO_HOME%\bin32\drrun.exe -syntax_intel %ARGS%
popd