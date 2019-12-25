#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.16.1)
project("ebpf")

function(ebpfCommonEbpf)
  add_library(ebpf OBJECT
    include/tob/ebpf/bpfmap.h
    include/tob/ebpf/types.h
    include/tob/ebpf/typedbpfmap.h

    include/tob/ebpf/tracepointevent.h
    src/tracepointevent.cpp

    include/tob/ebpf/perfeventarray.h
    src/perfeventarray.cpp

    include/tob/ebpf/llvm_utils.h
    src/llvm_utils.cpp

    include/tob/ebpf/ebpf_utils.h
    src/ebpf_utils.cpp

    include/tob/ebpf/sectionmemorymanager.h
    src/sectionmemorymanager.cpp

    include/tob/ebpf/bpfsyscallinterface.h
    src/bpfsyscallinterface.cpp
  )

  target_include_directories(ebpf PUBLIC include)

  target_link_libraries(ebpf PUBLIC
    thirdparty_llvm
    thirdparty_libbpf

    error
    utils
  )
endfunction()

ebpfCommonEbpf()
