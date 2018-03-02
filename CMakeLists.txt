cmake_minimum_required(VERSION 3.4)

option(test "Build all tests." OFF)

project(bbtrace)

set (CMAKE_CXX_STANDARD 11)

if (MSVC)
  add_library(bbtrace_core STATIC clients/bbtrace_core.c clients/branchlut2.cpp)
  target_compile_definitions(bbtrace_core PUBLIC WINDOWS X86_32)
  target_include_directories(bbtrace_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/clients $ENV{DYNAMORIO_HOME}/include)

  find_package(DynamoRIO 6.0)
  if (NOT DynamoRIO_FOUND)
    message(FATAL_ERROR "DynamoRIO package required to build")
  endif(NOT DynamoRIO_FOUND)

  if (test)
    # enable_testing()

    add_executable(test_app tests/test_app.cpp)
    set_target_properties(test_app PROPERTIES COMPILE_FLAGS /EHa)

    add_library(test_bbtrace SHARED tests/test_bbtrace.c)
    target_link_libraries(test_bbtrace bbtrace_core)

    configure_DynamoRIO_client(test_bbtrace)

    # add_test(RevengiTests test_bbtrace)
    # drrun.exe -c test_bbtrace.dll -- test_app.exe > ..\tests\test_bbtrace.expect 2>&1
  endif()

  add_library(bbtrace SHARED clients/bbtrace.c)
  target_link_libraries(bbtrace bbtrace_core)

  configure_DynamoRIO_client(bbtrace)
  use_DynamoRIO_extension(bbtrace drmgr)
  use_DynamoRIO_extension(bbtrace drwrap)
  use_DynamoRIO_extension(bbtrace drcontainers)

  add_library(instrace SHARED samples/instrace_x86.c samples/utils.c)
  configure_DynamoRIO_client(instrace)
  use_DynamoRIO_extension(instrace drcontainers)
  use_DynamoRIO_extension(instrace drmgr)
  use_DynamoRIO_extension(instrace drreg)
  use_DynamoRIO_extension(instrace drx)
  target_compile_definitions(instrace PUBLIC OUTPUT_TEXT)

  add_library(instrcalls SHARED samples/instrcalls.c samples/utils.c)
  configure_DynamoRIO_client(instrcalls)
  use_DynamoRIO_extension(instrcalls drmgr)
  use_DynamoRIO_extension(instrcalls drsyms)
  use_DynamoRIO_extension(instrcalls drx)
endif()

add_executable(bbtrace_util clients/bbtrace_util.cpp)
if (MSVC)
  target_compile_definitions(bbtrace_util PUBLIC WINDOWS X86_32)
  set_target_properties(bbtrace_util PROPERTIES COMPILE_FLAGS "/EHsc /Zi")
endif()
