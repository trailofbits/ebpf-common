/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include <linux/bpf.h>

#include <tob/utils/uniquefd.h>
#include <tob/utils/uniquemappedmemory.h>

namespace tob::ebpf {
using BPFProgram = std::vector<struct bpf_insn>;
using BPFProgramMap = std::unordered_map<std::string, BPFProgram>;

struct PerfEventOutput final {
  std::size_t processor_index;
  utils::UniqueMappedMemory::Ref memory;
  utils::UniqueFd fd;
};
} // namespace tob::ebpf
