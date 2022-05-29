/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

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
  NotAPointer,
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
  InvalidPath,
  TempStorageRequired,
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

  /// getElementPtr output
  struct ElementPtr final {
    /// BTF type id
    std::uint32_t btf_type_id{};

    /// The LLVM type of the opaque pointer
    llvm::Type *pointer_type{nullptr};

    /// The opaque pointer
    llvm::Value *opaque_pointer{nullptr};
  };

  /// Obtains a pointer to the specified field
  virtual Result<ElementPtr, LLVMBridgeError>
  getElementPtr(llvm::IRBuilder<> &builder, llvm::Value *opaque_pointer,
                llvm::Type *pointer_type, const std::string &path,
                llvm::Value *temp_storage = nullptr,
                llvm::BasicBlock *read_failed_bb = nullptr) const = 0;

  /// Obtains a pointer to the specified field
  virtual Result<ElementPtr, LLVMBridgeError>
  getElementPtr(llvm::IRBuilder<> &builder, llvm::Value *opaque_pointer,
                const std::string &pointer_type, const std::string &path,
                llvm::Value *temp_storage = nullptr,
                llvm::BasicBlock *read_failed_bb = nullptr) const = 0;

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
