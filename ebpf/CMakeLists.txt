#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

add_library("ebpf" OBJECT
  include/tob/ebpf/bpfmap.h
  include/tob/ebpf/types.h
  include/tob/ebpf/typedbpfmap.h
  include/tob/ebpf/structure.h

  include/tob/ebpf/cpu.h
  src/cpu.cpp

  include/tob/ebpf/ievent.h
  src/ievent.cpp

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

  src/tracepointevent.h
  src/tracepointevent.cpp

  src/kprobe_helpers.h
  src/kprobe_helpers.cpp

  src/kprobeevent.h
  src/kprobeevent.cpp

  src/uprobeevent.h
  src/uprobeevent.cpp

  include/tob/ebpf/iclangcompiler.h
  src/iclangcompiler.cpp

  src/clangcompiler.h
  src/clangcompiler.cpp

  src/bpf_helpers.h
  src/ebpf_common_helpers.h
)

target_include_directories("ebpf" PUBLIC include)

target_link_libraries("ebpf"
  PRIVATE
    "ebpfcommon_cxx_settings"

  PUBLIC
    "error"
    "utils"
    "btfparse"
    "external::llvm"
    "external::clang"
    "external::bpf"
)
