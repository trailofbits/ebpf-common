/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include <vector>

#include <linux/bpf.h>

#include <tob/ebpf/bpfsyscallinterface.h>

namespace tob::ebpf {
namespace {
template <int syscall_identifier>
llvm::Value *
assembleSystemCall(llvm::IRBuilder<> &builder,
                   llvm::Type *return_type = nullptr,
                   const llvm::ArrayRef<llvm::Value *> &argument_list = {}) {

  if (return_type == nullptr) {
    return_type = builder.getInt64Ty();
  }

  std::vector<llvm::Type *> argument_type_list;

  for (const auto &argument : argument_list) {
    argument_type_list.push_back(argument->getType());
  }

  auto function_type =
      llvm::FunctionType::get(return_type, argument_type_list, false);

  auto function =
      builder.CreateIntToPtr(builder.getInt64(syscall_identifier),
                             llvm::PointerType::getUnqual(function_type));

#if LLVM_VERSION_MAJOR < 11
  return builder.CreateCall(function, argument_list);
#else
  return builder.CreateCall(llvm::FunctionCallee(function_type, function),
                            argument_list);
#endif
}
} // namespace

struct BPFSyscallInterface::PrivateData final {
  PrivateData(llvm::IRBuilder<> &builder_) : builder(builder_) {}

  llvm::IRBuilder<> &builder;
};

StringErrorOr<BPFSyscallInterface::Ref>
BPFSyscallInterface::create(llvm::IRBuilder<> &builder) {
  try {
    return Ref(new BPFSyscallInterface(builder));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}

BPFSyscallInterface::~BPFSyscallInterface() {}

llvm::Value *BPFSyscallInterface::getCurrentTask() {
  return assembleSystemCall<BPF_FUNC_get_current_task>(d->builder);
}

llvm::Value *BPFSyscallInterface::getCurrentPidTgid() {
  return assembleSystemCall<BPF_FUNC_get_current_pid_tgid>(d->builder);
}

llvm::Value *BPFSyscallInterface::getCurrentUidGid() {
  return assembleSystemCall<BPF_FUNC_get_current_uid_gid>(d->builder);
}

llvm::Value *BPFSyscallInterface::getPrandomU32() {
  return assembleSystemCall<BPF_FUNC_get_prandom_u32>(d->builder,
                                                      d->builder.getInt32Ty());
}

llvm::Value *BPFSyscallInterface::ktimeGetNs() {
  return assembleSystemCall<BPF_FUNC_ktime_get_ns>(d->builder);
}

llvm::Value *BPFSyscallInterface::mapLookupElem(int map_fd, llvm::Value *key,
                                                llvm::Type *type) {
  auto map_value = pseudoMapFd(map_fd);

  return assembleSystemCall<BPF_FUNC_map_lookup_elem>(d->builder, type,
                                                      {map_value, key});
}

llvm::Value *BPFSyscallInterface::mapUpdateElem(int map_fd, llvm::Value *value,
                                                llvm::Value *key, int flags) {
  auto map_value = pseudoMapFd(map_fd);
  auto flags_value = d->builder.getInt64(static_cast<std::uint64_t>(flags));

  return assembleSystemCall<BPF_FUNC_map_update_elem>(
      d->builder, d->builder.getInt64Ty(),
      {map_value, key, value, flags_value});
}

llvm::Value *BPFSyscallInterface::mapDeleteElem(int map_fd, llvm::Value *key) {
  auto map_value = pseudoMapFd(map_fd);

  return assembleSystemCall<BPF_FUNC_map_delete_elem>(
      d->builder, d->builder.getInt64Ty(), {map_value, key});
}

llvm::Value *BPFSyscallInterface::probeRead(llvm::Value *dest,
                                            llvm::Value *size,
                                            llvm::Value *src) {
  return assembleSystemCall<BPF_FUNC_probe_read>(
      d->builder, d->builder.getInt64Ty(), {dest, size, src});
}

llvm::Value *BPFSyscallInterface::probeReadStr(llvm::Value *dest,
                                               std::size_t size,
                                               llvm::Value *src) {
  auto size_value = d->builder.getInt32(static_cast<std::uint32_t>(size));

  return assembleSystemCall<BPF_FUNC_probe_read_str>(
      d->builder, d->builder.getInt64Ty(), {dest, size_value, src});
}

llvm::Value *BPFSyscallInterface::getSmpProcessorId() {
  return assembleSystemCall<BPF_FUNC_get_smp_processor_id>(
      d->builder, d->builder.getInt32Ty());
}

llvm::Value *BPFSyscallInterface::perfEventOutput(llvm::Value *context,
                                                  int map_fd,
                                                  llvm::Value *data_ptr,
                                                  std::uint32_t data_size) {

  auto flags = std::numeric_limits<std::uint32_t>::max();

  auto map_value = pseudoMapFd(map_fd);
  auto flags_value = d->builder.getInt64(flags);
  auto size_value = d->builder.getInt32(data_size);

  return assembleSystemCall<BPF_FUNC_perf_event_output>(
      d->builder, d->builder.getInt64Ty(),
      {context, map_value, flags_value, data_ptr, size_value});
}

llvm::Value *BPFSyscallInterface::getCurrentCgroupId() {
  return assembleSystemCall<BPF_FUNC_get_current_cgroup_id>(
      d->builder, d->builder.getInt64Ty(), {});
}

llvm::Value *BPFSyscallInterface::getCurrentComm(llvm::Value *buffer,
                                                 std::uint32_t buffer_size) {
  auto buffer_size_value = d->builder.getInt32(buffer_size);

  return assembleSystemCall<BPF_FUNC_get_current_comm>(
      d->builder, d->builder.getInt64Ty(), {buffer, buffer_size_value});
}

void BPFSyscallInterface::tracePrintk(llvm::Value *format,
                                      llvm::Value *format_size,
                                      llvm::Value *op1, llvm::Value *op2,
                                      llvm::Value *op3) {

  std::vector<llvm::Value *> argument_list = {
      format,
      format_size,
  };

  for (const auto &op : {op1, op2, op3}) {
    if (op != nullptr) {
      argument_list.push_back(op);
    }
  }

  assembleSystemCall<BPF_FUNC_trace_printk>(d->builder, d->builder.getVoidTy(),
                                            argument_list);
}

void BPFSyscallInterface::overrideReturn(llvm::Value *context,
                                         std::uint64_t exit_code) {

  assembleSystemCall<BPF_FUNC_override_return>(
      d->builder, d->builder.getVoidTy(),
      {context, d->builder.getInt64(exit_code)});
}

BPFSyscallInterface::BPFSyscallInterface(llvm::IRBuilder<> &builder)
    : d(new PrivateData(builder)) {}

llvm::Function *BPFSyscallInterface::getPseudoFunction() {
  auto &insert_block = *d->builder.GetInsertBlock();
  auto &module = *insert_block.getModule();

  auto pseudo_function = module.getFunction("llvm.bpf.pseudo");

  if (pseudo_function == nullptr) {
    // clang-format off
    auto pseudo_function_type = llvm::FunctionType::get(
      d->builder.getInt64Ty(),

      {
        d->builder.getInt64Ty(),
        d->builder.getInt64Ty()
      },

      false
    );
    // clang-format on

    pseudo_function = llvm::Function::Create(pseudo_function_type,
                                             llvm::GlobalValue::ExternalLinkage,
                                             "llvm.bpf.pseudo", module);
  }

  return pseudo_function;
}

llvm::Value *BPFSyscallInterface::pseudoMapFd(int fd) {
  auto pseudo_function = getPseudoFunction();

  // clang-format off
  auto map_integer_address_value = d->builder.CreateCall(
    pseudo_function,

    {
      d->builder.getInt64(BPF_PSEUDO_MAP_FD),
      d->builder.getInt64(static_cast<std::uint64_t>(fd))
    }
  );
  // clang-format on

  auto &context = d->builder.getContext();

  return d->builder.CreateIntToPtr(map_integer_address_value,
                                   llvm::Type::getInt64PtrTy(context));
}
} // namespace tob::ebpf
