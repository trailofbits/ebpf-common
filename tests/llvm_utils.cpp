/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include <vector>

#include <doctest/doctest.h>

#include <tob/ebpf/llvm_utils.h>

namespace tob::ebpf {
SCENARIO("Determining LLVM structure size") {
  GIVEN("an LLVM structure type and module") {
    static const std::string kTestStructureName{"TestStructure"};

    llvm::LLVMContext llvm_context;

    // clang-format off
    std::vector<llvm::Type *> llvm_type_list = {
      llvm::Type::getInt64Ty(llvm_context),
      llvm::Type::getInt64Ty(llvm_context),
      llvm::Type::getInt64Ty(llvm_context),
      llvm::Type::getInt64Ty(llvm_context),
      llvm::Type::getInt16Ty(llvm_context),
      llvm::Type::getInt16Ty(llvm_context),
      llvm::Type::getInt8Ty(llvm_context),
      llvm::Type::getInt8Ty(llvm_context),
      llvm::Type::getInt8Ty(llvm_context)
    };
    // clang-format on

    auto llvm_struct = llvm::StructType::create(llvm_context, llvm_type_list,
                                                kTestStructureName, true);

    REQUIRE(llvm_struct != nullptr);

    auto llvm_module = createLLVMModule(llvm_context, "BPFModule");

    WHEN("determining the structure size") {
      auto structure_size = getTypeSize(*llvm_module.get(), llvm_struct);

      THEN("the amount of bytes required to hold it in memory is returned") {
        REQUIRE(structure_size == 39);
      }
    }
  }
}
} // namespace tob::ebpf
