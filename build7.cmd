@echo off

IF NOT EXIST build7 (
mkdir build7
)

pushd build7
rem cmake.exe -G "NMake Makefiles" -DDynamoRIO_DIR=%DYNAMORIO_HOME%\cmake -Dtest=ON ..
set DYNAMORIO_HOME=C:\DynamoRIO-7-RC
cmake -DDynamoRIO_DIR=%DYNAMORIO_HOME%\cmake ..
popd
