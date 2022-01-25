/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/Support/ManagedStatic.h>

#include <tob/ebpf/llvm_utils.h>

#include <tob/utils/architecture.h>

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

StringErrorOr<llvm::StructType *>
getPtRegsStructure(llvm::Module &module, const std::string &structure_name) {

  auto &context = module.getContext();

  auto architecture_exp = utils::getProcessorArchitecture();
  if (!architecture_exp.succeeded()) {
    return architecture_exp.error();
  }

  std::vector<llvm::Type *> type_list;
  auto architecture = architecture_exp.takeValue();

  switch (architecture) {
  case utils::Architecture::x86:
    type_list = std::vector<llvm::Type *>(17U, llvm::Type::getInt32Ty(context));
    break;

  case utils::Architecture::AArch32:
    type_list = std::vector<llvm::Type *>(18U, llvm::Type::getInt32Ty(context));
    break;

  case utils::Architecture::x64:
    type_list = std::vector<llvm::Type *>(21U, llvm::Type::getInt64Ty(context));
    break;

  case utils::Architecture::AArch64:
    // pt_regs.regs, from 0 to 30
    type_list = std::vector<llvm::Type *>(31U, llvm::Type::getInt64Ty(context));

    // pt_regs.sp
    type_list.push_back(llvm::Type::getInt64Ty(context));

    // pt_regs.pc
    type_list.push_back(llvm::Type::getInt64Ty(context));

    // pt_regs.pstate
    type_list.push_back(llvm::Type::getInt64Ty(context));

    break;
  }

  auto pt_regs_type =
      llvm::StructType::create(type_list, structure_name, false);

  if (pt_regs_type == nullptr) {
    return StringError::create("Failed to create the pt_regs type");
  }

  return pt_regs_type;
}

std::size_t getTypeSize(llvm::Module &module, llvm::Type *type) {
  llvm::DataLayout data_layout(&module);
  return data_layout.getTypeAllocSize(type);
}

std::optional<std::size_t> getOffsetOf(llvm::Module &module, llvm::Type *type,
                                       std::size_t index) {
  auto struct_type = llvm::dyn_cast<llvm::StructType>(type);
  if (struct_type == nullptr) {
    return std::nullopt;
  }

  const auto &struct_element_list = struct_type->elements();

  std::size_t offset{};
  for (std::uint32_t i{}; i < static_cast<std::uint32_t>(index); ++i) {
    auto element_type = struct_element_list[i];
    offset += getTypeSize(module, element_type);
  }

  return offset;
}

} // namespace tob::ebpf
