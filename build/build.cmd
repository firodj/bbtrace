@echo off

cmake.exe -G "NMake Makefiles" -DDynamoRIO_DIR=%DYNAMORIO_HOME%\cmake ..

IF [%ERRORLEVEL%]==[0] (
  nmake.exe /f Makefile
)