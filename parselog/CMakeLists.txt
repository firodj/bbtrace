cmake_minimum_required (VERSION 3.9.1)

#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)

project (PARSELOG)

set (CMAKE_CXX_STANDARD 11)

include_directories(${BBTRACE_SOURCE_DIR}/src)
#  ${CMAKE_SOURCE_DIR}/capstone/include

add_executable(parselog parselog.cpp)

if (MSVC)
  #target_include_directories (parselog PUBLIC ${CMAKE_SOURCE_DIR}/src)
  target_compile_definitions(parselog PUBLIC WINDOWS X86_32)
  set_target_properties(parselog PROPERTIES COMPILE_FLAGS "/EHsc /Zi")
#else()
  #set_target_properties(parselog PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
endif(MSVC)
