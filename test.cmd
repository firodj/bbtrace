@echo off

SET LOCAL=%~dp0
SET LOCAL=%LOCAL:~0,-1%

PUSHD build\RelWithDebInfo
%DYNAMORIO_HOME%\bin32\drrun.exe -logdir %LOCAL%\logs -c test_bbtrace.dll -- test_app.exe 2>&1
POPD
