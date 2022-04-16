/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "ebpf/src/llvmbridge.h"

#include <tob/ebpf/llvm_utils.h>

#include <doctest/doctest.h>

namespace tob::ebpf {

namespace {

struct TestContext final {
  TestContext()
      : llvm_module(ebpf::createLLVMModule(this->llvm_context, "LLVMBridge")),
        llvmbridge_context(*llvm_module.get()) {}

  llvm::LLVMContext llvm_context;
  std::unique_ptr<llvm::Module> llvm_module;
  LLVMBridge::Context llvmbridge_context;
};

using TestContextPtr = std::unique_ptr<TestContext>;

TestContextPtr createTestContext() {
  auto test_context = std::make_unique<TestContext>();
  LLVMBridge::initializeInternalTypes(test_context->llvmbridge_context);

  return test_context;
}

template <typename T>
bool checkTypeSize(const LLVMBridge::Context &context, const T &btf_type,
                   std::optional<std::uint32_t> opt_expected_size) {

  auto opt_size = LLVMBridge::getBTFTypeSize(context, btf_type);
  if (opt_size.has_value() != opt_expected_size.has_value()) {
    return false;
  }

  if (!opt_size.has_value()) {
    return true;
  }

  return opt_size.value() == opt_expected_size.value();
}

void checkPaddingType(const LLVMBridge::Context &context,
                      std::uint32_t btf_type_id,
                      std::uint32_t expected_byte_size) {
  REQUIRE(context.btf_type_map.count(btf_type_id) == 1);

  const auto &btf_type = context.btf_type_map.at(btf_type_id);
  REQUIRE(std::holds_alternative<ArrayBTFType>(btf_type));

  const auto &array_btf_type = std::get<ArrayBTFType>(btf_type);
  CHECK(array_btf_type.type == LLVMBridge::kInternalByteTypeID);
  CHECK(array_btf_type.nelems == expected_byte_size);
}

void checkStructurePadding(const LLVMBridge::Context &context,
                           const StructBTFType &btf_struct_type,
                           std::size_t member_index,
                           std::uint32_t expected_offset,
                           std::uint32_t expected_size) {
  REQUIRE(member_index < btf_struct_type.member_list.size());
  const auto &member = btf_struct_type.member_list.at(member_index);

  CHECK(member.offset == expected_offset);
  checkPaddingType(context, member.type, expected_size);
}

void checkBitfieldSize(const StructBTFType &btf_struct_type,
                       std::size_t member_index, std::uint32_t expected_offset,
                       std::uint32_t expected_size) {
  REQUIRE(member_index < btf_struct_type.member_list.size());
  const auto &member = btf_struct_type.member_list.at(member_index);

  CHECK(member.offset == expected_offset);
  REQUIRE(member.opt_bitfield_size.has_value());
  CHECK(member.opt_bitfield_size.value() == expected_size);
}

void checkBitfieldMapping(const LLVMBridge::Context &context,
                          const StructBTFType &original_btf_struct_type,
                          std::size_t original_bitfield_index,
                          std::uint32_t btf_type_id,
                          std::size_t expected_storage_index) {

  REQUIRE(original_bitfield_index <
          original_btf_struct_type.member_list.size());

  const auto &original_bitfield =
      original_btf_struct_type.member_list.at(original_bitfield_index);

  REQUIRE(original_bitfield.opt_bitfield_size.has_value());
  auto expected_bitfield_size = original_bitfield.opt_bitfield_size.value();

  REQUIRE(original_bitfield.opt_name.has_value());
  const auto &name = original_bitfield.opt_name.value();

  REQUIRE(context.btf_struct_mapping.count(btf_type_id) == 1);
  const auto &struct_mapping = context.btf_struct_mapping.at(btf_type_id);

  auto field_mapping_it = std::find_if(
      struct_mapping.begin(), struct_mapping.end(),

      [&name](const LLVMBridge::StructFieldMapping &field_mapping) -> bool {
        if (!field_mapping.opt_name.has_value()) {
          return false;
        }

        return field_mapping.opt_name.value() == name;
      });

  REQUIRE(field_mapping_it != struct_mapping.end());
  const auto &field_mapping = *field_mapping_it;

  CHECK(field_mapping.index == expected_storage_index);
  CHECK(field_mapping.type == original_bitfield.type);
  CHECK(!field_mapping.as_union);

  REQUIRE(field_mapping.opt_mask.has_value());
  const auto &mask = field_mapping.opt_mask.value();
  CHECK(mask.bit_size == expected_bitfield_size);

  auto updated_struct_it = context.btf_type_map.find(btf_type_id);
  REQUIRE(updated_struct_it != context.btf_type_map.end());

  const auto &updated_struct =
      std::get<StructBTFType>(updated_struct_it->second);

  REQUIRE(expected_storage_index < updated_struct.member_list.size());

  const auto &bitfield_storage =
      updated_struct.member_list.at(expected_storage_index);

  auto expected_bit_offset = original_bitfield.offset - bitfield_storage.offset;
  CHECK(mask.bit_offset == expected_bit_offset);
}

} // namespace

TEST_CASE("LLVMBridge::preprocessStructureType") {
  SUBCASE("Bitfields, simple") {
    static const StructBTFType kBitfieldsTestStructure = {
        {"bitfields"},
        4,
        {
            {
                {"member01"},
                LLVMBridge::kInternalByteTypeID,
                16,
                {2},
            },

            {
                {"member02"},
                LLVMBridge::kInternalByteTypeID,
                25,
                {2},
            },
        },
    };

    auto test_context = createTestContext();
    auto &context = test_context->llvmbridge_context;

    context.btf_type_map.insert({1, {kBitfieldsTestStructure}});
    auto opt_error = LLVMBridge::preprocessStructureType(
        context, kBitfieldsTestStructure, 1);

    REQUIRE(!opt_error.has_value());

    const auto &btf_type = context.btf_type_map.at(1);
    const auto &struct_btf_type = std::get<StructBTFType>(btf_type);

    // The bitfields should have been collapsed into one spanning
    // the whole size of the structure
    REQUIRE(struct_btf_type.member_list.size() == 1);
    checkBitfieldSize(struct_btf_type, 0, 0, 32);
    checkBitfieldMapping(context, kBitfieldsTestStructure, 0, 1, 0);
  }

  SUBCASE("Bitfields, with padding at the end") {
    static const StructBTFType kBitfieldsTestStructure = {
        {"bitfields"},
        8,
        {
            {
                // This bitfield is not starting at offset 0
                {"member01"},
                LLVMBridge::kInternalByteTypeID,
                7,
                {2},
            },

            {
                // This bitfield does not directly follow the previous one
                // so there is a gap between them
                //
                // Additionally, the complete size is not byte-aligned
                {"member02"},
                LLVMBridge::kInternalByteTypeID,
                25,
                {8},
            },
        },
    };

    auto test_context = createTestContext();
    auto &context = test_context->llvmbridge_context;

    context.btf_type_map.insert({1, {kBitfieldsTestStructure}});
    auto opt_error = LLVMBridge::preprocessStructureType(
        context, kBitfieldsTestStructure, 1);

    REQUIRE(!opt_error.has_value());

    const auto &btf_type = context.btf_type_map.at(1);
    const auto &struct_btf_type = std::get<StructBTFType>(btf_type);

    // This is what we are expecting to find:
    //
    // 0: bitfield storage: member01
    // 1: padding
    REQUIRE(struct_btf_type.member_list.size() == 2);
    checkBitfieldSize(struct_btf_type, 0, 0, 40);
    checkStructurePadding(context, struct_btf_type, 1, 40, 3);
    checkBitfieldMapping(context, kBitfieldsTestStructure, 0, 1, 0);
  }

  SUBCASE("Bitfields, with additional padding") {
    static const StructBTFType kBitfieldsTestStructure = {
        {"bitfields"},
        16,
        {
            {
                // This bitfield is not starting at offset 0. It should
                // also be followed by padding up until member02
                {"member01"},
                LLVMBridge::kInternalByteTypeID,
                13,
                {2},
            },

            {
                // This normal struct member will split the bitfield
                // in two
                {"member02"},
                LLVMBridge::kInternalByteTypeID,
                32,
                std::nullopt,
            },

            {
                // This bitfield does not directly follow the previous one
                // so there is a gap between them
                //
                // Additionally, the complete size is not byte-aligned
                {"member03"},
                LLVMBridge::kInternalByteTypeID,
                64,
                {3},
            },
        },
    };

    auto test_context = createTestContext();
    auto &context = test_context->llvmbridge_context;

    context.btf_type_map.insert({1, {kBitfieldsTestStructure}});
    auto opt_error = LLVMBridge::preprocessStructureType(
        context, kBitfieldsTestStructure, 1);

    REQUIRE(!opt_error.has_value());

    const auto &btf_type = context.btf_type_map.at(1);
    const auto &struct_btf_type = std::get<StructBTFType>(btf_type);

    // This is what we are expecting to find:
    //
    // 0: bitfield storage: member01
    // 1: member02
    // 2: padding
    // 3: bitfield storage: member03
    // 4: padding
    REQUIRE(struct_btf_type.member_list.size() == 5);

    checkBitfieldSize(struct_btf_type, 0, 0, 16);
    checkBitfieldSize(struct_btf_type, 3, 40, 32);

    checkStructurePadding(context, struct_btf_type, 1, 16, 2);
    checkStructurePadding(context, struct_btf_type, 4, 72, 7);

    checkBitfieldMapping(context, kBitfieldsTestStructure, 0, 1, 0);
    checkBitfieldMapping(context, kBitfieldsTestStructure, 2, 1, 3);
  }

  SUBCASE("Bitfields, multiple ones per storage") {
    static const StructBTFType kBitfieldsTestStructure = {
        {"bitfields"},
        4,
        {
            {
                {"member01"},
                LLVMBridge::kInternalByteTypeID,
                16,
                {2},
            },

            {
                {"member02"},
                LLVMBridge::kInternalByteTypeID,
                20,
                {2},
            },

            {
                {"member03"},
                LLVMBridge::kInternalByteTypeID,
                30,
                {1},
            },
        },
    };

    auto test_context = createTestContext();
    auto &context = test_context->llvmbridge_context;

    context.btf_type_map.insert({1, {kBitfieldsTestStructure}});
    auto opt_error = LLVMBridge::preprocessStructureType(
        context, kBitfieldsTestStructure, 1);

    REQUIRE(!opt_error.has_value());

    const auto &btf_type = context.btf_type_map.at(1);
    const auto &struct_btf_type = std::get<StructBTFType>(btf_type);

    // This is what we are expecting to find:
    //
    // 0: bitfield storage: member01 + member02 + member03
    REQUIRE(struct_btf_type.member_list.size() == 1);

    checkBitfieldSize(struct_btf_type, 0, 0, 32);

    checkBitfieldMapping(context, kBitfieldsTestStructure, 0, 1, 0);
    checkBitfieldMapping(context, kBitfieldsTestStructure, 1, 1, 0);
    checkBitfieldMapping(context, kBitfieldsTestStructure, 2, 1, 0);
  }
}

TEST_CASE("LLVMBridge::preprocessUnionType") {
  static const UnionBTFType kTestUnion = {
      {"test_union"},
      8,
      {
          {
              {"member01"},
              LLVMBridge::kInternalByteTypeID,
              0,
              std::nullopt,
          },

          {
              {"member02"},
              LLVMBridge::kInternalByteTypeID,
              8,
              std::nullopt,
          },
      },
  };

  auto test_context = createTestContext();
  auto &context = test_context->llvmbridge_context;

  context.btf_type_map.insert({1, {kTestUnion}});
  auto opt_error = LLVMBridge::preprocessUnionType(context, kTestUnion, 1);
  REQUIRE(!opt_error.has_value());

  REQUIRE(context.btf_struct_mapping.count(1) == 1);
  const auto &struct_mapping = context.btf_struct_mapping.at(1);
  REQUIRE(struct_mapping.size() == 2);

  REQUIRE(context.btf_type_map.count(1) == 1);
  const auto &updated_union_type = context.btf_type_map.at(1);
  REQUIRE(std::holds_alternative<UnionBTFType>(updated_union_type));

  const auto &updated_union = std::get<UnionBTFType>(updated_union_type);
  REQUIRE(updated_union.member_list.size() == 2);
}

TEST_CASE("LLVMBridge::initializeInternalTypes") {
  auto test_context = createTestContext();
  const auto &context = test_context->llvmbridge_context;

  REQUIRE(context.btf_type_map.count(LLVMBridge::kInternalByteTypeID) == 1);

  const auto &btf_type =
      context.btf_type_map.at(LLVMBridge::kInternalByteTypeID);

  REQUIRE(std::holds_alternative<IntBTFType>(btf_type));

  const auto &int_btf_type = std::get<IntBTFType>(btf_type);
  CHECK(!int_btf_type.name.empty());
  CHECK(int_btf_type.size == 1);
  CHECK(int_btf_type.encoding == IntBTFType::Encoding::None);
  CHECK(int_btf_type.offset == 0);
  CHECK(int_btf_type.bits == 8);
}

TEST_CASE("LLVMBridge::parsePath") {
  auto opt_path_component_list =
      LLVMBridge::parsePath("first.second[0][1].third[2][3].fourth[0]");

  REQUIRE(opt_path_component_list.has_value());

  {
    const auto &path_component_list = opt_path_component_list.value();
    REQUIRE(path_component_list.size() == 4);

    CHECK(path_component_list[0].name == "first");
    CHECK(path_component_list[0].index_list.size() == 0);

    CHECK(path_component_list[1].name == "second");
    CHECK(path_component_list[1].index_list.size() == 2);
    CHECK(path_component_list[1].index_list[0] == 0);
    CHECK(path_component_list[1].index_list[1] == 1);

    CHECK(path_component_list[2].name == "third");
    CHECK(path_component_list[2].index_list.size() == 2);
    CHECK(path_component_list[2].index_list[0] == 2);
    CHECK(path_component_list[2].index_list[1] == 3);

    CHECK(path_component_list[3].name == "fourth");
    CHECK(path_component_list[3].index_list.size() == 1);
    CHECK(path_component_list[3].index_list[0] == 0);
  }

  opt_path_component_list =
      LLVMBridge::parsePath(" first.second[0][1].third[2][3].fourth[0]");

  CHECK(!opt_path_component_list.has_value());

  opt_path_component_list =
      LLVMBridge::parsePath("first .second[0][1].third[2][3].fourth[0]");

  CHECK(!opt_path_component_list.has_value());

  opt_path_component_list =
      LLVMBridge::parsePath("first.second [0][1].third[2][3].fourth[0]");

  CHECK(!opt_path_component_list.has_value());

  opt_path_component_list =
      LLVMBridge::parsePath("first.second[0] [1].third[2][3].fourth[0]");

  CHECK(!opt_path_component_list.has_value());

  opt_path_component_list =
      LLVMBridge::parsePath("first.second[0][1] .third[2][3].fourth[0]");

  CHECK(!opt_path_component_list.has_value());

  opt_path_component_list =
      LLVMBridge::parsePath("first.second[ 0][1].third[2][3].fourth[0]");

  CHECK(!opt_path_component_list.has_value());

  opt_path_component_list =
      LLVMBridge::parsePath("first.second[0 ][1].third[2][3].fourth[0]");

  CHECK(!opt_path_component_list.has_value());

  opt_path_component_list =
      LLVMBridge::parsePath("first!.second[0][1].third[2][3].fourth[0]");

  CHECK(!opt_path_component_list.has_value());

  opt_path_component_list =
      LLVMBridge::parsePath("first.second[0!][1].third[2][3].fourth[0]");

  CHECK(!opt_path_component_list.has_value());

  opt_path_component_list =
      LLVMBridge::parsePath("first.second[0][1].third[2][3].fourth[0] ");

  CHECK(!opt_path_component_list.has_value());

  opt_path_component_list = LLVMBridge::parsePath("[10]");
  REQUIRE(opt_path_component_list.has_value());

  {
    const auto &path_component_list = opt_path_component_list.value();
    REQUIRE(path_component_list.size() == 1);

    CHECK(path_component_list[0].name.empty());
    CHECK(path_component_list[0].index_list.size() == 1);
  }
}

TEST_CASE("LLVMBridge::isBitfield") {
  StructBTFType::Member member;
  CHECK(!LLVMBridge::isBitfield(member));

  member.opt_bitfield_size = 0;
  CHECK(!LLVMBridge::isBitfield(member));

  member.opt_bitfield_size = 1;
  CHECK(LLVMBridge::isBitfield(member));
}

TEST_CASE("LLVMBridge::expandBitfield") {
  StructBTFType::Member source;
  StructBTFType::Member destination;

  CHECK(!LLVMBridge::expandBitfield(destination, source));

  source.opt_bitfield_size = 0;
  CHECK(!LLVMBridge::expandBitfield(destination, source));

  source.opt_bitfield_size = std::nullopt;
  destination.opt_bitfield_size = 0;

  CHECK(!LLVMBridge::expandBitfield(destination, source));

  source.opt_bitfield_size = 0;
  destination.opt_bitfield_size = 0;

  CHECK(!LLVMBridge::expandBitfield(destination, source));

  source.opt_bitfield_size = 4;
  destination.opt_bitfield_size = 12;

  CHECK(!LLVMBridge::expandBitfield(destination, source));

  source.offset = 12;

  CHECK(LLVMBridge::expandBitfield(destination, source));
  REQUIRE(destination.opt_bitfield_size.has_value());
  CHECK(destination.opt_bitfield_size.value() == 16);
  CHECK(destination.offset == 0);
}

TEST_CASE("LLVMBridge::getBTFTypeSize") {
  auto test_context = createTestContext();
  const auto &context = test_context->llvmbridge_context;

  BTFType btf_type;
  CHECK(LLVMBridge::getBTFTypeSize(context, btf_type) == std::nullopt);

  ArrayBTFType array_type;
  array_type.nelems = 10;
  array_type.type = LLVMBridge::kInternalByteTypeID;
  CHECK(checkTypeSize(context, array_type, array_type.nelems * 8));

  IntBTFType int_type;
  int_type.size = 2;
  CHECK(checkTypeSize(context, int_type, int_type.size * 8));

  CHECK(checkTypeSize(context, PtrBTFType{}, sizeof(void *) * 8));

  StructBTFType struct_type;
  struct_type.size = 10;
  CHECK(checkTypeSize(context, struct_type, struct_type.size * 8));

  UnionBTFType union_type;
  union_type.size = 10;
  CHECK(checkTypeSize(context, union_type, union_type.size * 8));

  EnumBTFType enum_type;
  enum_type.size = 4;
  CHECK(checkTypeSize(context, enum_type, enum_type.size * 8));

  FwdBTFType fwd_type;
  CHECK(checkTypeSize(context, fwd_type, std::nullopt));

  TypedefBTFType typedef_type;
  typedef_type.type = LLVMBridge::kInternalByteTypeID;
  CHECK(checkTypeSize(context, typedef_type, 8));

  VolatileBTFType volatile_type;
  volatile_type.type = LLVMBridge::kInternalByteTypeID;
  CHECK(checkTypeSize(context, volatile_type, 8));

  ConstBTFType const_type;
  const_type.type = LLVMBridge::kInternalByteTypeID;
  CHECK(checkTypeSize(context, const_type, 8));

  RestrictBTFType restrict_type;
  CHECK(checkTypeSize(context, restrict_type, std::nullopt));

  FuncBTFType func_type;
  CHECK(checkTypeSize(context, func_type, std::nullopt));

  FuncProtoBTFType func_proto_type;
  CHECK(checkTypeSize(context, func_proto_type, std::nullopt));

  VarBTFType var_type;
  CHECK(checkTypeSize(context, var_type, std::nullopt));

  DataSecBTFType data_sec_type;
  CHECK(checkTypeSize(context, data_sec_type, std::nullopt));

  FloatBTFType float_type;
  float_type.size = 4;
  CHECK(checkTypeSize(context, float_type, 32));
}

TEST_CASE("LLVMBridge::generatePaddingBTFArrayType") {
  auto test_context = createTestContext();
  auto &context = test_context->llvmbridge_context;

  auto padding_id1 = LLVMBridge::generatePaddingBTFArrayType(context, 10);
  REQUIRE(context.btf_type_map.count(padding_id1) == 1);
  REQUIRE(IBTF::getBTFTypeKind(context.btf_type_map.at(padding_id1)) ==
          BTFKind::Array);

  CHECK(std::get<ArrayBTFType>(context.btf_type_map.at(padding_id1)).nelems ==
        10);

  CHECK(std::get<ArrayBTFType>(context.btf_type_map.at(padding_id1)).type ==
        LLVMBridge::kInternalByteTypeID);

  auto opt_size = LLVMBridge::getBTFTypeSize(context, padding_id1);
  REQUIRE(opt_size.has_value());
  CHECK(opt_size.value() == 80);

  auto padding_id2 = LLVMBridge::generatePaddingBTFArrayType(context, 20);
  REQUIRE(context.btf_type_map.count(padding_id2) == 1);
  REQUIRE(IBTF::getBTFTypeKind(context.btf_type_map.at(padding_id2)) ==
          BTFKind::Array);

  CHECK(std::get<ArrayBTFType>(context.btf_type_map.at(padding_id2)).nelems ==
        20);

  CHECK(std::get<ArrayBTFType>(context.btf_type_map.at(padding_id2)).type ==
        LLVMBridge::kInternalByteTypeID);

  opt_size = LLVMBridge::getBTFTypeSize(context, padding_id2);
  REQUIRE(opt_size.has_value());
  CHECK(opt_size.value() == 160);

  auto padding_id3 = LLVMBridge::generatePaddingBTFArrayType(context, 30);
  REQUIRE(context.btf_type_map.count(padding_id3) == 1);
  REQUIRE(IBTF::getBTFTypeKind(context.btf_type_map.at(padding_id3)) ==
          BTFKind::Array);

  CHECK(std::get<ArrayBTFType>(context.btf_type_map.at(padding_id3)).nelems ==
        30);

  CHECK(std::get<ArrayBTFType>(context.btf_type_map.at(padding_id3)).type ==
        LLVMBridge::kInternalByteTypeID);

  opt_size = LLVMBridge::getBTFTypeSize(context, padding_id3);
  REQUIRE(opt_size.has_value());
  CHECK(opt_size.value() == 240);
}

TEST_CASE("LLVMBridge::locate") {
  StructBTFType test_struct01;
  test_struct01.opt_name = "test_struct01";
  test_struct01.member_list = {
      {
          {"member01"},
          2,
          0,
          std::nullopt,
      },

      {
          {"member02"},
          2,
          0,
          std::nullopt,
      },

      {
          {"member03"},
          2,
          0,
          std::nullopt,
      },
  };

  StructBTFType test_struct02;
  test_struct02.opt_name = "test_struct02";
  test_struct02.member_list = {
      {
          {"byte01"},
          LLVMBridge::kInternalByteTypeID,
          0,
          std::nullopt,
      },
  };

  auto test_context = createTestContext();

  // In this case, `byte01` should not be reachable
  {
    auto &context = test_context->llvmbridge_context;
    context.btf_type_map.insert({1, test_struct01});
    context.btf_type_map.insert({2, test_struct02});

    REQUIRE(!LLVMBridge::preprocessTypes(context).has_value());
    auto opt_mapping = LLVMBridge::locate(context, 1, "byte01");
    REQUIRE(!opt_mapping.has_value());

    opt_mapping = LLVMBridge::locate(context, 1, "member01");
    REQUIRE(opt_mapping.has_value());
    const auto &member01_mapping = opt_mapping.value();
    REQUIRE(member01_mapping.size() == 1);
    REQUIRE(member01_mapping[0].opt_name.has_value());
    CHECK(member01_mapping[0].opt_name.value() == "member01");

    opt_mapping = LLVMBridge::locate(context, 1, "member02");
    REQUIRE(opt_mapping.has_value());
    const auto &member02_mapping = opt_mapping.value();
    REQUIRE(member02_mapping.size() == 1);
    REQUIRE(member02_mapping[0].opt_name.has_value());
    CHECK(member02_mapping[0].opt_name.value() == "member02");

    opt_mapping = LLVMBridge::locate(context, 1, "member03");
    REQUIRE(opt_mapping.has_value());
    const auto &member03_mapping = opt_mapping.value();
    REQUIRE(member03_mapping.size() == 1);
    REQUIRE(member03_mapping[0].opt_name.has_value());
    CHECK(member03_mapping[0].opt_name.value() == "member03");
  }

  // Make the first member unnamed so that `byte01` is brought into
  // scope
  test_context = createTestContext();

  {
    test_struct01.member_list[0].opt_name = std::nullopt;

    auto &context = test_context->llvmbridge_context;
    context.btf_type_map.insert({1, test_struct01});
    context.btf_type_map.insert({2, test_struct02});

    REQUIRE(!LLVMBridge::preprocessTypes(context).has_value());
    auto opt_mapping = LLVMBridge::locate(context, 1, "byte01");
    REQUIRE(opt_mapping.has_value());
    const auto &byte01_mapping = opt_mapping.value();
    REQUIRE(byte01_mapping.size() == 2);
    CHECK(!byte01_mapping[0].opt_name.has_value());
    REQUIRE(byte01_mapping[1].opt_name.has_value());
    CHECK(byte01_mapping[1].opt_name.value() == "byte01");

    opt_mapping = LLVMBridge::locate(context, 1, "member01");
    REQUIRE(!opt_mapping.has_value());

    opt_mapping = LLVMBridge::locate(context, 1, "member02");
    REQUIRE(opt_mapping.has_value());
    const auto &member02_mapping = opt_mapping.value();
    REQUIRE(member02_mapping.size() == 1);
    REQUIRE(member02_mapping[0].opt_name.has_value());
    CHECK(member02_mapping[0].opt_name.value() == "member02");

    opt_mapping = LLVMBridge::locate(context, 1, "member03");
    REQUIRE(opt_mapping.has_value());
    const auto &member03_mapping = opt_mapping.value();
    REQUIRE(member03_mapping.size() == 1);
    REQUIRE(member03_mapping[0].opt_name.has_value());
    CHECK(member03_mapping[0].opt_name.value() == "member03");
  }
}

} // namespace tob::ebpf
