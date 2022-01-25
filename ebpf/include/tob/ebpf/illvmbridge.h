//
// Copyright (c) 2021-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

#pragma once

#include <btfparse/ibtf.h>

#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>

using namespace btfparse;

namespace tob::ebpf {

enum class LLVMBridgeErrorCode {
  Unknown,
  MemoryAllocationFailure,
  UnsupportedBTFType,
  MissingDependency,
  NotFound,
  InvalidStructureMemberOffset,
  UnalignedStructureMember,
  InvalidStructSize,
  InvalidStructurePath,
  NotAStructPointer,
  TypeIsNotIndexed,
  InternalError,
  InvalidBTFType,
  StructurePaddingError,
  BitfieldError,
};

struct LLVMBridgeErrorCodePrinter final {
  std::string operator()(const LLVMBridgeErrorCode &error_code) const;
};

using LLVMBridgeError =
    btfparse::Error<LLVMBridgeErrorCode, LLVMBridgeErrorCodePrinter>;

class ILLVMBridge {
public:
  using Ptr = std::unique_ptr<ILLVMBridge>;
  static Result<Ptr, LLVMBridgeError> create(llvm::Module &module,
                                             const IBTF &btf);

  virtual btfparse::Result<llvm::Type *, LLVMBridgeError>
  getType(const std::string &name) const = 0;

  virtual std::optional<LLVMBridgeError>
  read(llvm::IRBuilder<> &builder, llvm::Value *dest, llvm::Value *src,
       const std::string &path, llvm::BasicBlock *read_failed_bb) const = 0;

  ILLVMBridge() = default;
  virtual ~ILLVMBridge() = default;

  ILLVMBridge(const ILLVMBridge &) = delete;
  ILLVMBridge &operator=(const ILLVMBridge &) = delete;
};

} // namespace tob::ebpf
