cmake_minimum_required(VERSION 3.9)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

option(test "Build all tests." OFF)

project(BBTRACE)

set (CMAKE_CXX_STANDARD 11)

if (MSVC)
  add_library(bbtrace_core STATIC
      src/bbtrace_core.c src/codecache.c
      src/synchro.c src/winapi.c)
  target_compile_definitions(bbtrace_core PUBLIC WINDOWS X86_32)
  target_include_directories(bbtrace_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src $ENV{DYNAMORIO_HOME}/include)
  if (CMAKE_BUILD_TYPE STREQUAL Debug)
    set_target_properties(bbtrace_core PROPERTIES COMPILE_FLAGS /MTd)
  else ()
    set_target_properties(bbtrace_core PROPERTIES COMPILE_FLAGS /MT)
  endif()

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

  add_library(bbtrace SHARED src/bbtrace.cpp)
  target_link_libraries(bbtrace bbtrace_core)

  configure_DynamoRIO_client(bbtrace)
  use_DynamoRIO_extension(bbtrace drmgr)
  use_DynamoRIO_extension(bbtrace drwrap)
  use_DynamoRIO_extension(bbtrace drutil)
  use_DynamoRIO_extension(bbtrace drcontainers)

  if (CMAKE_BUILD_TYPE STREQUAL Debug)
  else()
    set_target_properties(bbtrace PROPERTIES LINK_FLAGS /INCREMENTAL:NO)
  endif()
endif()

add_subdirectory (parselog)
