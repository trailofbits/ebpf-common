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

  return builder.CreateCall(function, argument_list);
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

void BPFSyscallInterface::overrideReturn(llvm::Value *context,
                                         std::uint64_t exit_code) {

  assembleSystemCall<BPF_FUNC_override_return>(
      d->builder, d->builder.getVoidTy(),
      {context, d->builder.getInt64(exit_code)});
}

llvm::Value *BPFSyscallInterface::getCurrentPidTgid() {
  return assembleSystemCall<BPF_FUNC_get_current_pid_tgid>(d->builder);
}

llvm::Value *BPFSyscallInterface::getPrandomU32() {
  return assembleSystemCall<BPF_FUNC_get_prandom_u32>(d->builder,
                                                      d->builder.getInt32Ty());
}

BPFSyscallInterface::BPFSyscallInterface(llvm::IRBuilder<> &builder)
    : d(new PrivateData(builder)) {}
} // namespace tob::ebpf
