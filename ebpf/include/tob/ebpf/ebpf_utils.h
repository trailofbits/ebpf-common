/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include <linux/version.h>

#include <llvm/IR/Module.h>

#include <tob/ebpf/iperfevent.h>
#include <tob/ebpf/types.h>
#include <tob/error/error.h>

namespace tob::ebpf {
StringErrorOr<BPFProgramMap> compileModule(llvm::Module &module);

StringErrorOr<PerfEventOutput>
createPerfEventOutputForCPU(std::size_t processor_index,
                            std::size_t bpf_output_size);

StringErrorOr<utils::UniqueFd> loadProgram(const BPFProgram &program,
                                           IPerfEvent &perf_event);
StringErrorOr<utils::UniqueFd>
loadProgram(const BPFProgram &program,
            bpf_prog_type program_type = BPF_PROG_TYPE_UNSPEC);

StringErrorOr<std::uint32_t> getLinuxKernelVersionCode();
} // namespace tob::ebpf
