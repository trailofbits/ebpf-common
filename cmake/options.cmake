#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.14.6)

if(NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Release" AND
   NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Debug" AND
   NOT "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")

  set(default_cmake_build_type "RelWithDebInfo")

  if(NOT "${CMAKE_BUILD_TYPE}" STREQUAL "")
    message(WARNING "Invalid build type specified: ${CMAKE_BUILD_TYPE}")
  endif()

  message(WARNING "Setting CMAKE_BUILD_TYPE to ${default_cmake_build_type}")
  set(CMAKE_BUILD_TYPE "${default_cmake_build_type}" CACHE STRING "Build type (default ${default_cmake_build_type})" FORCE)
endif()

set(EBPF_COMMON_TOOLCHAIN_PATH "" CACHE PATH "Toolchain path")

option(EBPF_COMMON_ENABLE_TESTS "Set to ON to build the tests")
option(EBPF_COMMON_ENABLE_SANITIZERS "Set to ON to enable sanitizers. Only available when compiling with Clang")

if(NOT "${EBPF_COMMON_TOOLCHAIN_PATH}" STREQUAL "")
  if(NOT EXISTS "${EBPF_COMMON_TOOLCHAIN_PATH}")
    message(FATAL_ERROR "ebpf-common - The specified toolchain path is not valid: ${EBPF_COMMON_TOOLCHAIN_PATH}")
  endif()

  set(default_libcpp_setting true)

  set(CMAKE_C_COMPILER "${EBPF_COMMON_TOOLCHAIN_PATH}/usr/bin/clang" CACHE PATH "Path to the C compiler" FORCE)
  set(CMAKE_CXX_COMPILER "${EBPF_COMMON_TOOLCHAIN_PATH}/usr/bin/clang++" CACHE PATH "Path to the C++ compiler" FORCE)

  set(CMAKE_SYSROOT "${EBPF_COMMON_TOOLCHAIN_PATH}" CACHE PATH "CMake sysroot for find_package scripts")

  message(STATUS "ebpf-common - Toolchain enabled")
else()
  set(default_libcpp_setting false)
  message(STATUS "ebpf-common - Toolchain disabled")
endif()

option(EBPF_COMMON_ENABLE_LIBCPP "Set to ON to build with libc++" ${default_libcpp_setting})
set(EBPF_COMMON_ZLIB_LIBRARY_PATH "" CACHE FILEPATH "Specifies the path of the zlib library file to use. If left empty the system one will be used")
