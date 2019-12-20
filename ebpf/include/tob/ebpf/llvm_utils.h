/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <memory>

#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Module.h>

#include <tob/error/error.h>

namespace tob::ebpf {
class LLVMInitializer final {
public:
  LLVMInitializer();
  ~LLVMInitializer();

  LLVMInitializer(const LLVMInitializer &) = delete;
  LLVMInitializer &operator=(const LLVMInitializer &) = delete;
};

extern const LLVMInitializer kLLVMInitializer;

std::unique_ptr<llvm::Module> createLLVMModule(llvm::LLVMContext &llvm_context,
                                               const std::string &module_name);

std::size_t getLLVMStructureSize(llvm::StructType *llvm_struct,
                                 llvm::Module *module);
} // namespace tob::ebpf
