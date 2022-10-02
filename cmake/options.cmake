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

  if(NOT "${CMAKE_BUILD_TYPE}" STREQUAL "")
    message(FATAL_ERROR "ebpf-common - Invalid build type specified: ${CMAKE_BUILD_TYPE}")
  endif()
endif()

option(EBPF_COMMON_ENABLE_TESTS "Set to ON to build the tests")

set(CMAKE_EXPORT_COMPILE_COMMANDS true CACHE BOOL "Export the compile_commands.json file (forced)" FORCE)
