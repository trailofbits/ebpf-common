#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.21.4)
project("ebpf-common")

include("cmake/options.cmake")
include("cmake/settings.cmake")

add_subdirectory("libraries")
add_subdirectory("ebpf")
add_subdirectory("error")
add_subdirectory("utils")

if(EBPF_COMMON_ENABLE_TESTS)
  message(STATUS "ebpf-common - Tests are enabled")

  add_executable("ebpf-common-tests"
    tests/main.cpp

    tests/bpfmap.cpp
    tests/erroror.cpp
    tests/llvm_utils.cpp
    tests/llvmbridge.cpp
    tests/sectionmemorymanager.cpp
    tests/tracepointdescriptor.cpp
    tests/typedbpfmap.cpp
    tests/uniqueref.cpp
  )

  target_link_libraries("ebpf-common-tests" PRIVATE
    "ebpfcommon_cxx_settings"
    "ebpf"
    "error"
    "utils"
    "external::doctest"
  )

  target_include_directories("ebpf-common-tests" PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
  )

  add_custom_target(run-ebpf-common-tests
    COMMAND "$<TARGET_FILE:ebpf-common-tests>"
    COMMENT "Running ebpf-common tests"
  )

else()
  message(STATUS "ebpf-common - Tests are disabled")
endif()
