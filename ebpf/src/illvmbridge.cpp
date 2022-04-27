/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "llvmbridge.h"

#include <unordered_map>

#include <tob/ebpf/illvmbridge.h>

namespace tob::ebpf {

namespace {

const std::unordered_map<LLVMBridgeErrorCode, std::string>
    kErrorTranslationMap = {
        {LLVMBridgeErrorCode::Unknown, "Unknown"},
        {LLVMBridgeErrorCode::MemoryAllocationFailure,
         "MemoryAllocationFailure"},
        {LLVMBridgeErrorCode::UnsupportedBTFType, "UnsupportedBTFType"},
        {LLVMBridgeErrorCode::MissingDependency, "MissingDependency"},
        {LLVMBridgeErrorCode::NotFound, "NotFound"},
        {LLVMBridgeErrorCode::InvalidStructureMemberOffset,
         "InvalidStructureMemberOffset"},
        {LLVMBridgeErrorCode::InvalidStructSize, "InvalidStructSize"},
        {LLVMBridgeErrorCode::InvalidStructurePath, "InvalidStructurePath"},
        {LLVMBridgeErrorCode::NotAStructPointer, "NotAStructPointer"},
        {LLVMBridgeErrorCode::TypeIsNotIndexed, "TypeIsNotIndexed"},
        {LLVMBridgeErrorCode::InternalError, "InternalError"},
        {LLVMBridgeErrorCode::StructurePaddingError, "StructurePaddingError"},
        {LLVMBridgeErrorCode::BitfieldError, "BitfieldError"},
};

}

std::string LLVMBridgeErrorCodePrinter::operator()(
    const LLVMBridgeErrorCode &error_code) const {
  auto error_it = kErrorTranslationMap.find(error_code);
  if (error_it == kErrorTranslationMap.end()) {
    return "UnknownErrorCode:" + std::to_string(static_cast<int>(error_code));
  }

  return error_it->second;
}

Result<ILLVMBridge::Ptr, LLVMBridgeError>
ILLVMBridge::create(llvm::Module &module, const IBTF &btf) {
  try {
    return Ptr(new LLVMBridge(module, btf));

  } catch (const std::bad_alloc &) {
    return LLVMBridgeError(LLVMBridgeErrorCode::MemoryAllocationFailure);

  } catch (const LLVMBridgeError &e) {
    return e;
  }
}

} // namespace tob::ebpf
