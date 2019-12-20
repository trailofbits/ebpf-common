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
namespace {
const std::string kKprobeTypePath{
    "/sys/bus/event_source/devices/kprobe/subsystem/devices/kprobe/type"};

const std::string kKprobeReturnBitPath{"/sys/devices/kprobe/format/retprobe"};

StringErrorOr<std::string> readFile(const std::string &path) {
  std::ifstream input_file(path);

  std::stringstream buffer;
  buffer << input_file.rdbuf();

  if (!input_file) {
    return StringError::create("Failed to read the input file");
  }

  return buffer.str();
}

StringErrorOr<std::uint32_t> getKProbeType() {
  auto buffer_exp = readFile(kKprobeTypePath);
  if (!buffer_exp.succeeded()) {
    return buffer_exp.error();
  }

  auto buffer = buffer_exp.takeValue();

  char *integer_terminator{nullptr};
  auto integer_value = std::strtol(buffer.data(), &integer_terminator, 10);

  if (!(integer_terminator != nullptr && std::isspace(*integer_terminator))) {
    return StringError::create("Failed to parse the integer value");
  }

  return static_cast<std::uint32_t>(integer_value);
}

StringErrorOr<bool> getKprobeReturnBit() {
  auto buffer_exp = readFile(kKprobeReturnBitPath);
  if (!buffer_exp.succeeded()) {
    return buffer_exp.error();
  }

  auto buffer = buffer_exp.takeValue();

  auto value_ptr = buffer.data() + std::strlen("config:");
  if (value_ptr >= buffer.data() + buffer.size()) {
    return StringError::create("Invalid buffer contents");
  }

  char *integer_terminator{nullptr};
  auto integer_value = std::strtol(value_ptr, &integer_terminator, 10);

  if (!(integer_terminator != nullptr && std::isspace(*integer_terminator))) {
    return StringError::create("Failed to parse the integer value");
  }

  if (integer_value == 0) {
    return false;

  } else if (integer_value == 1) {
    return true;

  } else {
    return StringError::create("Unexpected integer value");
  }
}
} // namespace

StringErrorOr<utils::UniqueFd>
createKprobeEvent(bool is_kretprobe, const std::string &function_name,
                  std::uint64_t offset, pid_t process_id) {

  struct perf_event_attr attr = {};
  attr.sample_period = 1;
  attr.wakeup_events = 1;
  attr.config2 = offset;
  attr.size = sizeof(attr);

  auto string_ptr = function_name.c_str();
  std::memcpy(&attr.config1, &string_ptr, sizeof(string_ptr));

  auto probe_type_exp = getKProbeType();
  if (!probe_type_exp.succeeded()) {
    return probe_type_exp.error();
  }

  attr.type = probe_type_exp.takeValue();

  if (is_kretprobe) {
    auto probe_return_bit_exp = getKprobeReturnBit();
    if (!probe_return_bit_exp.succeeded()) {
      return probe_return_bit_exp.error();
    }

    auto probe_return_bit = probe_return_bit_exp.takeValue();

    attr.config |= 1 << probe_return_bit;
  }

  int cpu_index;
  if (process_id != -1) {
    cpu_index = -1;
  } else {
    cpu_index = 0;
  }

  auto event_fd = syscall(__NR_perf_event_open, &attr, process_id, cpu_index,
                          -1, PERF_FLAG_FD_CLOEXEC);

  if (event_fd == -1) {
    return StringError::create("Failed to create the event");
  }

  utils::UniqueFd unique_fd;
  unique_fd.reset(static_cast<int>(event_fd));

  return unique_fd;
}

StringErrorOr<utils::UniqueFd>
createTracepointEvent(std::uint32_t event_identifier, pid_t process_id) {

  int cpu_index;
  if (process_id != -1) {
    cpu_index = -1;
  } else {
    cpu_index = 0;
  }

  struct perf_event_attr perf_attr = {};
  perf_attr.type = PERF_TYPE_TRACEPOINT;
  perf_attr.size = sizeof(struct perf_event_attr);
  perf_attr.config = event_identifier;
  perf_attr.sample_period = 1;
  perf_attr.sample_type = PERF_SAMPLE_RAW;
  perf_attr.wakeup_events = 1;
  perf_attr.disabled = 1;

  auto event_fd =
      static_cast<int>(::syscall(__NR_perf_event_open, &perf_attr, process_id,
                                 cpu_index, -1, PERF_FLAG_FD_CLOEXEC));

  if (event_fd == -1) {
    throw StringError::create("Failed to create the perf output");
  }

  utils::UniqueFd unique_fd;
  unique_fd.reset(static_cast<int>(event_fd));

  return unique_fd;
}

SuccessOrStringError closeEvent(utils::UniqueFd &event_fd) {
  if (event_fd.get() == -1) {
    return {};
  }

  if (ioctl(event_fd.get(), PERF_EVENT_IOC_DISABLE, 0) < 0) {
    return StringError::create("Failed to enable the perf BPF output");
  }

  event_fd.reset();
  return {};
}

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
                                           int event_fd,
                                           bpf_prog_type program_type,
                                           std::uint32_t linux_version) {

  // Load the program
  union bpf_attr attr = {};
  attr.prog_type = program_type;
  attr.insns = reinterpret_cast<__aligned_u64>(program.data());
  attr.insn_cnt = static_cast<std::uint32_t>(program.size());
  attr.log_level = 1U;
  attr.kern_version = linux_version;

  static const std::string kProgramLicense{"GPL"};
  attr.license = reinterpret_cast<__aligned_u64>(kProgramLicense.c_str());

  // We could in theory try to load the program with no log buffer at first, and
  // if it fails, try again with it. I prefer to call this once and have
  // everything. There's a gotcha though; if this buffer is not big enough to
  // contain the whole disasm of the program in text form, the load will fail.
  // We have a limit of 4096 instructions, so let's use a huge buffer to take
  // into account at least 4096 lines + decorations
  std::vector<char> log_buffer((4096U + 100U) * 80U);
  attr.log_buf = reinterpret_cast<__u64>(log_buffer.data());
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

    const auto &log_buffer_ptr = log_buffer.data();
    if (std::strlen(log_buffer_ptr) != 0U) {
      error_message += log_buffer_ptr;
    } else {
      error_message += "No error output received from the kernel.";
    }

    error_message += " errno was set to " + std::to_string(errno);

    return StringError::create(error_message);
  }

  if (ioctl(event_fd, PERF_EVENT_IOC_SET_BPF, output.get()) < 0) {
    return StringError::create(
        "Failed to attach the perf output to the BPF program: " +
        std::to_string(errno));
  }

  if (ioctl(event_fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
    return StringError::create("Failed to enable the perf output: " +
                               std::to_string(errno));
  }

  return output;
}
} // namespace tob::ebpf
