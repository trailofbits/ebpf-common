#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

function(configureSanitizers target_name)
  if(NOT EBPF_COMMON_ENABLE_SANITIZERS)
  message(STATUS "ebpf-common - Sanitizers: disabled")
    return()
  endif()

  if(NOT "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    message(STATUS "ebpf-common - Sanitizers: disabled (not supported)")
    return()
  endif()

  set(flag_list
    -fno-omit-frame-pointer -fsanitize=undefined,address
  )

  target_compile_options("${target_name}" INTERFACE ${flag_list})
  target_link_options("${target_name}" INTERFACE ${flag_list})

  message(STATUS "ebpf-common - Sanitizers: enabled")

  if(NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    message(WARNING "ebpf-common - Debug builds are preferred when using sanitizers")
  endif()
endfunction()
