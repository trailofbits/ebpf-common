/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include <llvm/ExecutionEngine/MCJIT.h>

#include <tob/ebpf/llvm_utils.h>

namespace tob::ebpf {
LLVMInitializer::LLVMInitializer() {
  LLVMInitializeBPFTarget();
  LLVMInitializeBPFTargetMC();
  LLVMInitializeBPFTargetInfo();
  LLVMInitializeBPFAsmPrinter();
  LLVMLinkInMCJIT();
}

LLVMInitializer::~LLVMInitializer() { llvm::llvm_shutdown(); }

const LLVMInitializer kLLVMInitializer;

std::unique_ptr<llvm::Module> createLLVMModule(llvm::LLVMContext &llvm_context,
                                               const std::string &module_name) {

  auto llvm_module = std::make_unique<llvm::Module>(module_name, llvm_context);

  llvm_module->setTargetTriple("bpf-pc-linux");
  llvm_module->setDataLayout("e-m:e-p:64:64-i64:64-n32:64-S128");

  return llvm_module;
}

std::size_t getLLVMStructureSize(llvm::StructType *llvm_struct,
                                 llvm::Module *module) {

  llvm::DataLayout data_layout(module);

  auto size =
      static_cast<std::size_t>(data_layout.getTypeAllocSize(llvm_struct));

  return size;
}
} // namespace tob::ebpf
