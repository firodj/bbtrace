pushd build\RelWithDebInfo
%DYNAMORIO_HOME%\bin32\drrun.exe -c test_bbtrace.dll -- test_app.exe 2>&1
popd
