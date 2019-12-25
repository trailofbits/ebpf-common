/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <memory>

#include <llvm/IR/IRBuilder.h>

#include <tob/error/error.h>

namespace tob::ebpf {
class BPFSyscallInterface final {
public:
  using Ref = std::unique_ptr<BPFSyscallInterface>;
  static StringErrorOr<Ref> create(llvm::IRBuilder<> &builder);

  ~BPFSyscallInterface();

  void overrideReturn(llvm::Value *context, std::uint64_t exit_code);
  llvm::Value *getCurrentPidTgid();
  llvm::Value *getPrandomU32();

  BPFSyscallInterface(const BPFSyscallInterface &) = delete;
  BPFSyscallInterface &operator=(const BPFSyscallInterface &) = delete;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  BPFSyscallInterface(llvm::IRBuilder<> &builder);
};
} // namespace tob::ebpf
