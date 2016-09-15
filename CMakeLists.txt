cmake_minimum_required(VERSION 3.4)

project(rE-pSX)

find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

add_library(avgbbsize SHARED avgbbsize.c)
configure_DynamoRIO_client(avgbbsize)