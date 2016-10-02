@echo off

IF NOT EXIST build (
mkdir build
)

pushd build
rem cmake.exe -G "NMake Makefiles" -DDynamoRIO_DIR=%DYNAMORIO_HOME%\cmake -Dtest=ON ..
cmake -G "Visual Studio 12" -DDynamoRIO_DIR=d:\LIB\dynamorio\build\cmake ..
popd
