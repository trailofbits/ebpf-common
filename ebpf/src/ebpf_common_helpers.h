/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include <string>

namespace tob::ebpf {

// clang-format off
const std::string kEbpfCommonHelpers{R"src(
#define offsetof(t, d) \
  __builtin_offsetof(t, d)

#define bpf_probe_read_struct_member_helper(FunctionName, StructureType, MemberName, structure_ptr, dest_ptr) \
  FunctionName( \
    dest_ptr, \
    sizeof(*dest_ptr), \
    ((const u8 *) structure_ptr) + offsetof(StructureType, MemberName))

#define bpf_probe_read_struct_member(StructureType, MemberName, structure_ptr, dest_ptr) \
  bpf_probe_read_struct_member_helper(bpf_probe_read, StructureType, \
                                      MemberName, structure_ptr, dest_ptr)

#define bpf_probe_read_user_struct_member(StructureType, MemberName, structure_ptr, dest_ptr) \
  bpf_probe_read_struct_member_helper(bpf_probe_read_user, StructureType, \
                                      MemberName, structure_ptr, dest_ptr)

#define bpf_probe_read_kernel_struct_member(StructureType, MemberName, structure_ptr, dest_ptr) \
  bpf_probe_read_struct_member_helper(bpf_probe_read_kernel, StructureType, \
                                      MemberName, structure_ptr, dest_ptr)

// This function is not really used; once we finished building
// the code, we look up all the callers and replace them
// with the actual llvm.bpf.pseudo intrinsic
extern u64 llvm_bpf_pseudo(u64 bpf_pseudo, u64 param);

// Converts a map file descriptor to a bpf_map struct pointer
// that can be passed to the BPF helpers
#define BPF_PSEUDO_MAP_FD(fd) \
  (struct bpf_map *) llvm_bpf_pseudo(1, fd)
)src"};
// clang-format on

} // namespace tob::ebpf
