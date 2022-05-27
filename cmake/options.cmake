#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

if(NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Release" AND
   NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Debug" AND
   NOT "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")

  set(default_cmake_build_type "RelWithDebInfo")

  if(NOT "${CMAKE_BUILD_TYPE}" STREQUAL "")
    message(WARNING "ebpf-common - Invalid build type specified: ${CMAKE_BUILD_TYPE}")
  endif()

  message(WARNING "ebpf-common - Setting CMAKE_BUILD_TYPE to ${default_cmake_build_type}")
  set(CMAKE_BUILD_TYPE "${default_cmake_build_type}" CACHE STRING "Build type (default ${default_cmake_build_type})" FORCE)
endif()

option(EBPF_COMMON_ENABLE_TESTS "Set to ON to build the tests")
option(EBPF_COMMON_ENABLE_SANITIZERS "Set to ON to enable sanitizers. Only available when compiling with Clang")
