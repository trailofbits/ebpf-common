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

  set(llvm_component_list
    core
    bpfcodegen
    executionengine
    mcjit
  )
 
  if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86_64")
    list(APPEND llvm_component_list x86codegen)

  elseif("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64")
    list(APPEND llvm_component_list aarch64codegen)

  else()
    message(FATAL_ERROR "Unsupported architecture: ${CMAKE_SYSTEM_PROCESSOR}")
  endif()

  llvm_map_components_to_libnames(llvm_library_list
    ${llvm_component_list}
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
