@echo off

IF NOT EXIST build (
mkdir build
)

pushd build
cmake.exe -G "NMake Makefiles" -DDynamoRIO_DIR=%DYNAMORIO_HOME%\cmake -Dtest=ON ..
popd