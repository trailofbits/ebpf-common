/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include <cstring>
#include <ctype.h>
#include <fstream>
#include <sstream>

#include <linux/perf_event.h>
#include <linux/unistd.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/Transforms/Utils/Cloning.h>

#include <tob/ebpf/ebpf_utils.h>
#include <tob/ebpf/sectionmemorymanager.h>

namespace tob::ebpf {
const std::string kLinuxVersionHeaderPath{"/usr/include/linux/version.h"};
const std::string kDefinitionName{"LINUX_VERSION_CODE"};
const std::string kProgramLicense{"GPL"};

StringErrorOr<BPFProgramMap> compileModule(llvm::Module &module) {
  auto module_copy = llvm::CloneModule(module);

  auto exec_engine_builder =
      std::make_unique<llvm::EngineBuilder>(std::move(module_copy));

  exec_engine_builder->setMArch("bpf");
  exec_engine_builder->setUseOrcMCJITReplacement(false);
  exec_engine_builder->setOptLevel(llvm::CodeGenOpt::Default);

  std::string builder_err_output;
  exec_engine_builder->setErrorStr(&builder_err_output);

  MemorySectionMap section_map;
  exec_engine_builder->setMCJITMemoryManager(
      std::make_unique<SectionMemoryManager>(section_map));

  std::unique_ptr<llvm::ExecutionEngine> execution_engine(
      exec_engine_builder->create());

  if (execution_engine == nullptr) {
    std::string error_message = "Failed to create the execution engine builder";
    if (!builder_err_output.empty()) {
      error_message += ": " + builder_err_output;
    }

    return StringError::create(error_message);
  }

  execution_engine->setProcessAllSections(true);
  execution_engine->finalizeObject();

  BPFProgramMap bpf_program_set;

  for (const auto &p : section_map) {
    auto section_name = p.first;
    auto bytecode_buffer = p.second.data;

    if (section_name.empty() || section_name[0] == '.') {
      continue;
    }

    BPFProgram program = {};
    auto instruction_count = bytecode_buffer.size() / sizeof(struct bpf_insn);

    for (std::size_t i = 0U; i < instruction_count; ++i) {
      struct bpf_insn instruction = {};

      auto source_ptr = bytecode_buffer.data() + (i * sizeof(struct bpf_insn));
      std::memcpy(&instruction, source_ptr, sizeof(instruction));

      program.push_back(instruction);
    }

    bpf_program_set.insert({section_name, std::move(program)});
  }

  if (bpf_program_set.empty()) {
    return StringError::create("No programs found");
  }

  return bpf_program_set;
}

StringErrorOr<PerfEventOutput>
createPerfEventOutputForCPU(std::size_t processor_index,
                            std::size_t bpf_output_size) {

  static const int kNullPid{-1};
  static const int kNullGroupFd{-1};
  static const int kNullFlags{0};

  PerfEventOutput perf_event_output;
  perf_event_output.processor_index = processor_index;

  {
    struct perf_event_attr attr {};
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_SW_BPF_OUTPUT;
    attr.sample_period = 1;
    attr.sample_type = PERF_SAMPLE_RAW;
    attr.wakeup_events = 1;
    attr.disabled = 1;

    auto perf_event_fd = ::syscall(__NR_perf_event_open, &attr, kNullPid,
                                   processor_index, kNullGroupFd, kNullFlags);

    if (perf_event_fd == -1) {
      return StringError::create("Failed to create the perf BPF output");
    }

    perf_event_output.fd.reset(static_cast<int>(perf_event_fd));
  }

  auto output_memory_exp = utils::UniqueMappedMemory::create(
      nullptr, bpf_output_size, PROT_READ | PROT_WRITE, MAP_SHARED,
      perf_event_output.fd.get(), 0);

  if (!output_memory_exp.succeeded()) {
    return output_memory_exp.error();
  }

  perf_event_output.memory = output_memory_exp.takeValue();

  if (ioctl(perf_event_output.fd.get(), PERF_EVENT_IOC_ENABLE, 0) < 0) {
    return StringError::create("Failed to enable the perf BPF output");
  }

  return perf_event_output;
}

StringErrorOr<utils::UniqueFd> loadProgram(const BPFProgram &program,
                                           IPerfEvent &perf_event) {

  bpf_prog_type program_type{};
  std::uint32_t linux_version{};

  switch (perf_event.type()) {
  case IPerfEvent::Type::Tracepoint: {
    program_type = BPF_PROG_TYPE_TRACEPOINT;
    break;
  }

  case IPerfEvent::Type::Kprobe:
  case IPerfEvent::Type::Kretprobe: {
    program_type = BPF_PROG_TYPE_KPROBE;

    auto linux_version_exp = getLinuxKernelVersionCode();
    if (!linux_version_exp.succeeded()) {
      return linux_version_exp.error();
    }

    linux_version = linux_version_exp.takeValue();
    break;
  }

  // TODO(alessandro): is this correct?
  case IPerfEvent::Type::Uprobe:
  case IPerfEvent::Type::Uretprobe: {
    program_type = BPF_PROG_TYPE_KPROBE;
    break;
  }

  default: {
    return StringError::create("Unsupported perf event type");
  }
  }

  // Load the program
  union bpf_attr attr = {};
  attr.prog_type = program_type;
  attr.insn_cnt = static_cast<std::uint32_t>(program.size());
  attr.log_level = 1U;
  attr.kern_version = linux_version;

  auto program_data_ptr = program.data();
  std::memcpy(&attr.insns, &program_data_ptr, sizeof(attr.insns));

  auto program_license_ptr = kProgramLicense.c_str();
  std::memcpy(&attr.license, &program_license_ptr, sizeof(attr.license));

  // We could in theory try to load the program with no log buffer at first, and
  // if it fails, try again with it. I prefer to call this once and have
  // everything. There's a gotcha though; if this buffer is not big enough to
  // contain the whole disasm of the program in text form, the load will fail.
  // We have a limit of 4096 instructions, so let's use a huge buffer to take
  // into account at least 4096 lines + decorations
  std::vector<char> log_buffer((4096U + 100U) * 80U, 0U);

  auto log_buffer_ptr = log_buffer.data();
  std::memcpy(&attr.log_buf, &log_buffer_ptr, sizeof(attr.log_buf));

  attr.log_size = static_cast<__u32>(log_buffer.size());

  utils::UniqueFd output;

  {
    errno = 0;
    auto fd = static_cast<int>(
        ::syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr)));

    output.reset(fd);
  }

  if (output.get() < 0) {
    std::string error_message{"The program could not be loaded: "};

    if (std::strlen(log_buffer_ptr) != 0U) {
      error_message += log_buffer_ptr;
    } else {
      error_message += "No error output received from the kernel.";
    }

    error_message += " errno was set to " + std::to_string(errno);

    return StringError::create(error_message);
  }

  if (ioctl(perf_event.fd(), PERF_EVENT_IOC_SET_BPF, output.get()) < 0) {
    return StringError::create(
        "Failed to attach the BPF program to the perf event: " +
        std::to_string(errno));
  }

  if (ioctl(perf_event.fd(), PERF_EVENT_IOC_ENABLE, 0) < 0) {
    return StringError::create("Failed to enable the perf event: " +
                               std::to_string(errno));
  }

  return output;
}

StringErrorOr<std::uint32_t> getLinuxKernelVersionCode() {
  std::string header_contents;

  {
    std::fstream linux_version_header(kLinuxVersionHeaderPath);
    if (!linux_version_header) {
      return StringError::create(
          "Failed to open the Linux kernel version header: " +
          kLinuxVersionHeaderPath);
    }

    std::stringstream buffer;
    buffer << linux_version_header.rdbuf();
    if (!linux_version_header) {
      return StringError::create(
          "Failed to read the Linux kernel version header: " +
          kLinuxVersionHeaderPath);
    }

    header_contents = buffer.str();
  }

  auto definition_index = header_contents.find(kDefinitionName);
  if (definition_index == std::string::npos) {
    return StringError::create("Failed to locate the LINUX_VERSION_CODE "
                               "definition in the Linux kernel version header");
  }

  auto base_index = definition_index + kDefinitionName.size() + 1;
  if (base_index >= header_contents.size()) {
    return StringError::create("Malformed Linux kernel version header");
  }

  std::size_t version_code_index{0U};

  while (base_index < header_contents.size()) {
    auto current_char = header_contents.at(base_index);

    if (current_char == '\n' || current_char == '\x00') {
      break;
    }

    if (std::isdigit(current_char)) {
      version_code_index = base_index;
      break;
    }

    ++base_index;
  }

  if (version_code_index == 0U) {
    return StringError::create(
        "Failed to locate the Linux kernel version code inside the header");
  }

  const char *version_code_ptr = header_contents.c_str() + version_code_index;

  char *field_terminator{nullptr};
  auto version_code = std::strtoul(version_code_ptr, &field_terminator, 10);
  if (field_terminator == nullptr || *field_terminator != '\n') {
    return StringError::create("Failed to parse the Linux kernel version code");
  }

  return static_cast<std::uint32_t>(version_code);
}
} // namespace tob::ebpf
