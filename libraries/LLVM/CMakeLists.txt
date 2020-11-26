#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.14.6)
project("LLVM")

function(ebpfCommonLibrariesLLVM)
  find_package(LLVM REQUIRED CONFIG)

  llvm_map_components_to_libnames(llvm_library_list
    core
    bpfcodegen
    x86codegen
    executionengine
    mcjit
  )

  add_library(thirdparty_llvm INTERFACE)
  target_link_libraries(thirdparty_llvm INTERFACE ${llvm_library_list})

  target_include_directories(thirdparty_llvm SYSTEM INTERFACE
    ${LLVM_INCLUDE_DIRS}
  )

  target_compile_definitions(thirdparty_llvm INTERFACE
    ${LLVM_DEFINITIONS}
    LLVM_VERSION_MAJOR=${LLVM_VERSION_MAJOR}
    LLVM_VERSION_MINOR=${LLVM_VERSION_MINOR}
  )

  # Ubuntu/Debian workaround
  if(EXISTS "/usr/include/llvm-${LLVM_VERSION_MAJOR}")
    target_include_directories(thirdparty_llvm SYSTEM INTERFACE
      "/usr/include/llvm-${LLVM_VERSION_MAJOR}"
    )
  endif()
endfunction()

ebpfCommonLibrariesLLVM()
