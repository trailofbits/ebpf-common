#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.14.6)

include("cmake/options.cmake")
include("cmake/sanitizers.cmake")
include("cmake/utils.cmake")

project("ebpf-common")

function(ebpfCommonMain)
  generateSettingsTargets()

  add_subdirectory("libraries")

  add_subdirectory("ebpf")
  add_subdirectory("error")
  add_subdirectory("utils")

  if(EBPF_COMMON_ENABLE_TESTS)
    message(STATUS "ebpf-common - Tests are enabled")
    generateEbpfCommonTests()

  else()
    message(STATUS "ebpf-common - Tests are disabled")
  endif()
endfunction()

function(generateEbpfCommonTests)
  add_executable(ebpf-common-tests
    tests/main.cpp

    tests/bpfmap.cpp
    tests/erroror.cpp
    tests/llvm_utils.cpp
    tests/sectionmemorymanager.cpp
    tests/tracepointdescriptor.cpp
    tests/typedbpfmap.cpp
    tests/uniqueref.cpp
  )

  target_link_libraries(ebpf-common-tests PRIVATE
    thirdparty_catch2

    ebpf
    error
    utils
  )

  add_custom_target(run-ebpf-common-tests
    COMMAND "$<TARGET_FILE:ebpf-common-tests>"
    COMMENT "Running ebpf-common tests"
  )
endfunction()

ebpfCommonMain()
