#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.14.6)
project("catch2")

function(ebpfCommonLibrariesCatch2)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_catch2 INTERFACE)
  target_include_directories(thirdparty_catch2 SYSTEM INTERFACE
    "${library_root}/single_include"
  )
endfunction()

ebpfCommonLibrariesCatch2()
