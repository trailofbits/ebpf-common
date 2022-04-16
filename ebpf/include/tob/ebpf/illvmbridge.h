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

/// LLVMBridge error codes
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

/// LLVMBridgeErrorCode printer
struct LLVMBridgeErrorCodePrinter final {
  std::string operator()(const LLVMBridgeErrorCode &error_code) const;
};

/// LLVMBridge errors
using LLVMBridgeError =
    btfparse::Error<LLVMBridgeErrorCode, LLVMBridgeErrorCodePrinter>;

/// A BTF to LLVM bridge
class ILLVMBridge {
public:
  /// A pointer to an LLVMBridge object
  using Ptr = std::unique_ptr<ILLVMBridge>;

  /// Creates a new LLVM bridge instance, importing the given BTF types
  static Result<Ptr, LLVMBridgeError> create(llvm::Module &module,
                                             const IBTF &btf);

  /// Returns the LLVM type for the specified type name
  virtual btfparse::Result<llvm::Type *, LLVMBridgeError>
  getType(const std::string &name) const = 0;

  /// Reads the `path` value from `src` into `dest`
  virtual std::optional<LLVMBridgeError>
  read(llvm::IRBuilder<> &builder, llvm::Value *dest, llvm::Value *src,
       const std::string &path, llvm::BasicBlock *read_failed_bb) const = 0;

  /// Constructor
  ILLVMBridge() = default;

  /// Destructor
  virtual ~ILLVMBridge() = default;

  /// Copy constructor (disabled)
  ILLVMBridge(const ILLVMBridge &) = delete;

  /// Copy assignment operator (disabled)
  ILLVMBridge &operator=(const ILLVMBridge &) = delete;
};

} // namespace tob::ebpf
