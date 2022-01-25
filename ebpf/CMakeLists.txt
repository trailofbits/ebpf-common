#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.14.6)
project("ebpf")

function(ebpfCommonEbpf)
  add_library(ebpf OBJECT
    include/tob/ebpf/bpfmap.h
    include/tob/ebpf/types.h
    include/tob/ebpf/typedbpfmap.h
    include/tob/ebpf/structure.h

    include/tob/ebpf/cpu.h
    src/cpu.cpp

    include/tob/ebpf/iperfevent.h
    src/iperfevent.cpp

    include/tob/ebpf/tracepointdescriptor.h
    src/tracepointdescriptor.cpp

    include/tob/ebpf/perfeventarray.h
    src/perfeventarray.cpp

    include/tob/ebpf/llvm_utils.h
    src/llvm_utils.cpp

    include/tob/ebpf/ebpf_utils.h
    src/ebpf_utils.cpp

    include/tob/ebpf/illvmbridge.h
    src/illvmbridge.cpp

    src/llvmbridge.h
    src/llvmbridge.cpp

    include/tob/ebpf/sectionmemorymanager.h
    src/sectionmemorymanager.cpp

    include/tob/ebpf/bpfsyscallinterface.h
    src/bpfsyscallinterface.cpp

    src/tracepointperfevent.h
    src/tracepointperfevent.cpp

    src/kprobe_helpers.h
    src/kprobe_helpers.cpp

    src/kprobeperfevent.h
    src/kprobeperfevent.cpp

    src/uprobeperfevent.h
    src/uprobeperfevent.cpp
  )

  target_include_directories(ebpf PUBLIC include)

  target_link_libraries(ebpf
    PRIVATE
      cxx_target_settings

    PUBLIC
      thirdparty_llvm
      thirdparty_libbpf
      error
      utils
      btfparse
  )
endfunction()

ebpfCommonEbpf()
