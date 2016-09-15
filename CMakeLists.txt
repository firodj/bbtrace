cmake_minimum_required(VERSION 3.4)

project(rE-pSX)

find_package(DynamoRIO 6.0)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

add_library(controlflow SHARED clients/controlflow.c)
configure_DynamoRIO_client(controlflow)
use_DynamoRIO_extension(controlflow drmgr)
use_DynamoRIO_extension(controlflow drwrap)
use_DynamoRIO_extension(controlflow drcontainers)