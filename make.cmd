@echo off

pushd build
rem nmake.exe /f Makefile %1 %2 %3 %4 %5 %6 %7 %8 %9
cmake --build . --config RelWithDebInfo
popd
