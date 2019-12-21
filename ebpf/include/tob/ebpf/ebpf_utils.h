/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include <linux/version.h>

#include <llvm/IR/Module.h>

#include <tob/ebpf/types.h>
#include <tob/error/error.h>

namespace tob::ebpf {
StringErrorOr<utils::UniqueFd>
createKprobeEvent(bool is_kretprobe, const std::string &function_name,
                  std::uint64_t offset, pid_t process_id);

StringErrorOr<utils::UniqueFd>
createTracepointEvent(std::uint32_t event_identifier, pid_t process_id);

SuccessOrStringError closeEvent(utils::UniqueFd &event_fd);

StringErrorOr<BPFProgramMap> compileModule(llvm::Module &module);

StringErrorOr<PerfEventOutput>
createPerfEventOutputForCPU(std::size_t processor_index,
                            std::size_t bpf_output_size);

StringErrorOr<utils::UniqueFd>
loadProgram(const BPFProgram &program, int event_fd, bpf_prog_type program_type,
            std::uint32_t linux_version = LINUX_VERSION_CODE);

StringErrorOr<std::uint32_t> getLinuxKernelVersionCode();
} // namespace tob::ebpf
