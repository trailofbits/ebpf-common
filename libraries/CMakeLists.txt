#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.14.6)

function(ebpfCommonLibraries)
  add_subdirectory("libbpf")
  add_subdirectory("LLVM")
  add_subdirectory("Catch2")
endfunction()

ebpfCommonLibraries()
