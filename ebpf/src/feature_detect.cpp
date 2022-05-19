/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include <llvm/IR/IRBuilder.h>
#include <tob/ebpf/ebpf_utils.h>
#include <tob/ebpf/feature_detect.h>
#include <tob/ebpf/llvm_utils.h>

namespace tob::ebpf {

bool FeatureDetection::isHelperImplemented(bpf_func_id id) {
  llvm::LLVMContext context;
  auto module = createLLVMModule(context, "feature_detect_helper");
  llvm::IRBuilder<> builder{context};

  auto function_type = llvm::FunctionType::get(builder.getInt64Ty(), false);

  auto function = builder.CreateIntToPtr(
      builder.getInt64(id), llvm::PointerType::getUnqual(function_type));

#if LLVM_VERSION_MAJOR < 11
  auto function_callee = function;
#else
  auto function_callee = llvm::FunctionCallee(function_type, function);
#endif

  builder.CreateCall(function_callee);
  builder.CreateRet(builder.getInt64(0));

  auto program_map_exp = compileModule(*module);
  if (!program_map_exp.succeeded()) {
    throw program_map_exp.error();
  }

  auto program_map = program_map_exp.takeValue();

  // Get the program and load it
  if (program_map.size() != 1U) {
    throw StringError::create("The program was not compiled");
  }

  auto &first_program = program_map.begin()->second;

  auto program_exp = loadProgram(first_program, BPF_PROG_TYPE_UNSPEC);
  if (!program_exp.succeeded()) {
    return false;
  }

  return true;
}

} // namespace tob::ebpf
