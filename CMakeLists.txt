cmake_minimum_required(VERSION 3.4)

option(test "Build all tests." OFF)

project(bbtrace)

find_package(DynamoRIO 6.0)
if (NOT DynamoRIO_FOUND)
	message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

add_library(bbtrace_core STATIC clients/bbtrace_core.c)
target_compile_definitions(bbtrace_core PUBLIC WINDOWS X86_32)
target_include_directories(bbtrace_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/clients $ENV{DYNAMORIO_HOME}/include)

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

add_executable(bbtrace_flow clients/bbtrace_flow.cpp)
set_target_properties(bbtrace_flow PROPERTIES COMPILE_FLAGS /EHsc)
target_link_libraries(bbtrace_flow bbtrace_core)
