cmake_minimum_required (VERSION 3.9.1)

#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)

project (PARSELOG)

set (CMAKE_CXX_STANDARD 14)

set(BUILD_EXAMPLES OFF CACHE BOOL "argh Examples")
set(BUILD_TESTS OFF CACHE BOOL "argh Tests")
set(REPLXX_BuildExamples OFF CACHE BOOL "Replxx Examples")

add_subdirectory(ext/replxx)
add_subdirectory(ext/argh)

include_directories(${BBTRACE_SOURCE_DIR}/src)
#  ${CMAKE_SOURCE_DIR}/capstone/include

add_library(parselog_core STATIC
    parsebuffer.cpp
    logparser.cpp
    logrunner.cpp
    serializer.cpp
)
if (MSVC)
  set_target_properties(parselog_core PROPERTIES COMPILE_FLAGS "/EHsc /Zi")
  target_compile_definitions(parselog_core PUBLIC WINDOWS X86_32)
endif(MSVC)

# Analyzer: parselog runner
add_executable(parselog main.cpp analyzer/printer.cpp)

if (MSVC)
  #target_include_directories (parselog PUBLIC ${CMAKE_SOURCE_DIR}/src)
  target_compile_definitions(parselog PUBLIC WINDOWS X86_32)
  set_target_properties(parselog PROPERTIES COMPILE_FLAGS "/EHsc /Zi")
#else()
  #set_target_properties(parselog PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
endif(MSVC)

target_link_libraries(parselog parselog_core replxx argh)

# Analyzer: grapher runner
add_executable(grapher main.cpp analyzer/grapher.cpp)

if (MSVC)
  target_compile_definitions(grapher PUBLIC WINDOWS X86_32)
  set_target_properties(grapher PROPERTIES COMPILE_FLAGS "/EHsc /Zi")
endif(MSVC)

target_link_libraries(grapher parselog_core replxx argh)
