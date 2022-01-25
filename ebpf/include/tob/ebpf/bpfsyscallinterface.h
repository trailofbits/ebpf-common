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

  llvm::Value *getCurrentTask();
  llvm::Value *getCurrentPidTgid();
  llvm::Value *getCurrentUidGid();

  llvm::Value *getPrandomU32();
  llvm::Value *ktimeGetNs();

  llvm::Value *mapLookupElem(int map_fd, llvm::Value *key, llvm::Type *type);

  llvm::Value *mapUpdateElem(int map_fd, llvm::Value *value, llvm::Value *key,
                             int flags);

  llvm::Value *mapDeleteElem(int map_fd, llvm::Value *key);

  llvm::Value *probeRead(llvm::Value *dest, llvm::Value *size,
                         llvm::Value *src);

  llvm::Value *probeReadStr(llvm::Value *dest, std::size_t size,
                            llvm::Value *src);

  llvm::Value *getSmpProcessorId();

  llvm::Value *perfEventOutput(llvm::Value *context, int map_fd,
                               llvm::Value *data_ptr, std::uint32_t data_size);

  llvm::Value *getCurrentCgroupId();
  llvm::Value *getCurrentComm(llvm::Value *buffer, std::uint32_t buffer_size);

  void tracePrintk(llvm::Value *format, llvm::Value *format_size,
                   llvm::Value *op1 = nullptr, llvm::Value *op2 = nullptr,
                   llvm::Value *op3 = nullptr);

  void overrideReturn(llvm::Value *context, std::uint64_t exit_code);

  BPFSyscallInterface(const BPFSyscallInterface &) = delete;
  BPFSyscallInterface &operator=(const BPFSyscallInterface &) = delete;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  BPFSyscallInterface(llvm::IRBuilder<> &builder);

  llvm::Function *getPseudoFunction();
  llvm::Value *pseudoMapFd(int fd);
};
} // namespace tob::ebpf
