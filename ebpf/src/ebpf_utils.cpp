/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include <btfparse/ibtf.h>
#include <cstring>
#include <ctype.h>
#include <fstream>
#include <iostream>
#include <linux/bpf.h>
#include <sstream>

#include <elf.h>
#include <linux/perf_event.h>
#include <linux/unistd.h>
#include <sys/ioctl.h>
#include <unistd.h>

#if __has_include("sys/auxv.h")
#include <sys/auxv.h>
#endif

#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/Transforms/Utils/Cloning.h>

#include <tob/ebpf/ebpf_utils.h>
#include <tob/ebpf/sectionmemorymanager.h>

namespace tob::ebpf {
const std::string kLinuxVersionHeaderPath{"/usr/include/linux/version.h"};
const std::string kDefinitionName{"LINUX_VERSION_CODE"};
const std::string kProgramLicense{"GPL"};

namespace {
StringErrorOr<std::uint32_t> getVersionCodeFromVersionHeader() {
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

template <typename T> const T *alignPointer(const T *ptr) {
  static const std::uintptr_t kAlignment{4U};

  std::uintptr_t address;
  std::memcpy(&address, &ptr, sizeof(address));

  address = (address + (kAlignment - 1)) & -kAlignment;

  const T *aligned_ptr;
  std::memcpy(&aligned_ptr, &address, sizeof(aligned_ptr));

  return aligned_ptr;
}

#if __has_include("sys/auxv.h")
StringErrorOr<std::uintptr_t> getVdsoBaseAddress() {
  auto address = static_cast<std::uintptr_t>(getauxval(AT_SYSINFO_EHDR));
  if (address == 0) {
    return StringError::create("Failed to locate the vDSO base address");
  }

  return address;
}

#else
StringErrorOr<std::uintptr_t> getVdsoBaseAddress() {
  std::ifstream maps_file("/proc/self/maps");
  if (!maps_file) {
    return StringError::create("Failed to open /proc/self/maps");
  }

  std::uintptr_t address{};

  for (std::string line; std::getline(maps_file, line);) {
    if (line.find("[vdso]") != std::string::npos) {
      auto delimiter = line.find("-");
      if (delimiter == std::string::npos) {
        return StringError::create("Failed to parse /proc/self/maps");
      }

      line.resize(delimiter);

      char *null_term_ptr{nullptr};
      address = static_cast<std::uintptr_t>(
          std::strtoull(line.c_str(), &null_term_ptr, 16));

      if (address == 0 || null_term_ptr == nullptr || *null_term_ptr != 0) {
        return StringError::create("Failed to parse /proc/self/maps");
      }

      return address;
    }
  }

  return StringError::create(
      "Failed to locate the vdso entry in /proc/self/maps");
}
#endif

StringErrorOr<std::uint32_t> getVersionCodeFromVdso() {
  auto integer_addr_res = getVdsoBaseAddress();
  if (!integer_addr_res.succeeded()) {
    return integer_addr_res.error();
  }

  auto integer_addr = integer_addr_res.takeValue();

  const std::uint8_t *header_ptr{nullptr};
  std::memcpy(&header_ptr, &integer_addr, sizeof(header_ptr));

  Elf64_Ehdr elf_header;
  std::memcpy(&elf_header, header_ptr, sizeof(elf_header));

  const auto section_header_size = elf_header.e_shentsize;

  for (Elf64_Half section_index{0}; section_index < elf_header.e_shnum;
       ++section_index) {

    auto section_header_ptr =
        header_ptr + elf_header.e_shoff + (section_index * section_header_size);

    Elf64_Shdr section_header;
    std::memcpy(&section_header, section_header_ptr, sizeof(section_header));

    if (section_header.sh_type != SHT_NOTE) {
      continue;
    }

    auto start_ptr = header_ptr + section_header.sh_offset;
    auto end_ptr = start_ptr + section_header.sh_size;

    for (auto ptr = start_ptr; ptr < end_ptr;) {
      Elf64_Nhdr note_header;
      std::memcpy(&note_header, ptr, sizeof(note_header));
      ptr += sizeof(note_header);

      std::string name(note_header.n_namesz - 1, '\0');
      std::memcpy(&name[0], ptr, name.size());
      ptr = alignPointer(ptr + note_header.n_namesz);

      std::vector<std::uint8_t> description(note_header.n_descsz, 0);
      std::memcpy(description.data(), ptr, description.size());
      ptr = alignPointer(ptr + note_header.n_descsz);

      if (name == "Linux" && description.size() == 4 &&
          note_header.n_type == 0) {
        std::uint32_t linux_version;
        std::memcpy(&linux_version, description.data(), sizeof(linux_version));

        return linux_version;
      }
    }
  }

  return StringError::create(
      "Failed to locate the linux version code note in the vDSO module");
}
} // namespace

StringErrorOr<BPFProgramMap> compileModule(llvm::Module &module) {
  auto module_copy = llvm::CloneModule(module);

  auto exec_engine_builder =
      std::make_unique<llvm::EngineBuilder>(std::move(module_copy));

  exec_engine_builder->setMArch("bpf");
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
                                           IEvent &event) {

  bpf_prog_type program_type{};
  std::uint32_t linux_version{};

  switch (event.type()) {
  case IEvent::Type::Tracepoint: {
    program_type = BPF_PROG_TYPE_TRACEPOINT;
    break;
  }

  case IEvent::Type::Kprobe:
  case IEvent::Type::Kretprobe:
  case IEvent::Type::Uprobe:
  case IEvent::Type::Uretprobe: {
    program_type = BPF_PROG_TYPE_KPROBE;

    auto linux_version_exp = getLinuxKernelVersionCode();
    if (!linux_version_exp.succeeded()) {
      return linux_version_exp.error();
    }

    linux_version = linux_version_exp.takeValue();
    break;
  }

  default: {
    return StringError::create("Unsupported event type");
  }
  }

  // Load the program
  union bpf_attr attr = {};
  attr.prog_type = program_type;
  attr.insn_cnt = static_cast<std::uint32_t>(program.size());
  attr.kern_version = linux_version;

  auto program_data_ptr = program.data();
  std::memcpy(&attr.insns, &program_data_ptr, sizeof(attr.insns));

  auto program_license_ptr = kProgramLicense.c_str();
  std::memcpy(&attr.license, &program_license_ptr, sizeof(attr.license));

  utils::UniqueFd output;

  {
    errno = 0;
    auto fd = static_cast<int>(
        ::syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr)));

    output.reset(fd);
  }

  if (output.get() < 0) {
    attr.log_level = 1 + 2 + 4;

    std::vector<char> log_buffer(1024U * 1024U * 10U, 0U);
    attr.log_size = static_cast<__u32>(log_buffer.size());

    auto log_buffer_ptr = log_buffer.data();
    std::memcpy(&attr.log_buf, &log_buffer_ptr, sizeof(attr.log_buf));

    errno = 0;
    auto fd = static_cast<int>(
        ::syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr)));

    if (fd < 0) {
      std::string error_message{"The program could not be loaded: "};

      if (std::strlen(log_buffer_ptr) != 0U) {
        error_message += log_buffer_ptr;
      } else {
        error_message += "No error output received from the kernel.";
      }

      error_message += " errno was set to " + std::to_string(errno);
      return StringError::create(error_message);
    }

    output.reset(fd);
  }

  if (ioctl(event.fd(), PERF_EVENT_IOC_SET_BPF, output.get()) < 0) {
    return StringError::create(
        "Failed to attach the BPF program to the perf event. Errno: " +
        std::to_string(errno));
  }

  if (ioctl(event.fd(), PERF_EVENT_IOC_ENABLE, 0) < 0) {
    return StringError::create("Failed to enable the perf event. Errno: " +
                               std::to_string(errno));
  }

  return output;
}

StringErrorOr<std::uint32_t> getLinuxKernelVersionCode() {
  auto version_exp = getVersionCodeFromVdso();
  if (version_exp.succeeded()) {
    return version_exp;
  }

  std::cerr << version_exp.error().message() << "\nAttempting to parse "
            << kLinuxVersionHeaderPath << "...\n";

  return getVersionCodeFromVersionHeader();
}
} // namespace tob::ebpf
