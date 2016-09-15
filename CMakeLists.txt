cmake_minimum_required(VERSION 3.4)

# Howto:
# \> mkdir build
# \> cd build
# build\> cmake -DDynamoRIO_DIR=%DYNAMORIO_HOME%/cmake ..
# build\> nmake -f Makefile

project(rE-pSX)

find_package(DynamoRIO 6.0)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

add_library(avgbbsize SHARED avgbbsize.c)
configure_DynamoRIO_client(avgbbsize)

add_executable(tracedump tracedump.c)
configure_DynamoRIO_standalone(tracedump)
configure_DynamoRIO_decoder(tracedump)