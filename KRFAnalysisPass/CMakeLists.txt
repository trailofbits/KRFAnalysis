cmake_minimum_required(VERSION 3.4)

find_package(LLVM 8 REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})

add_library( LLVMKRF MODULE
  KRF.cpp
  toctou.cpp
  reverseTaint.cpp
  )
