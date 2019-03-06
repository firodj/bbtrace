@echo off

set CONFIG=RelWithDebInfo

SET LOCAL=%~dp0
SET LOCAL=%LOCAL:~0,-1%

PUSHD bin\%CONFIG%

echo %cd%
IF NOT EXIST logs (
    mkdir logs
)

%DYNAMORIO_HOME%\bin32\drrun.exe -logdir %LOCAL%\bin\%CONFIG%\logs -c test_bbtrace.dll -- test_app.exe 2>&1
DEL bbtrace.dll.test_app.exe.*

rem %DYNAMORIO_HOME%\bin32\drrun.exe -logdir logs -c bbtrace.dll -- test_app.exe 2>&1
POPD

