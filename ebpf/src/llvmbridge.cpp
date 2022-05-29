/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "llvmbridge.h"

#include <btfparse/ibtf.h>
#include <cctype>
#include <cstdlib>
#include <llvm/IR/DerivedTypes.h>
#include <optional>
#include <tob/ebpf/bpfsyscallinterface.h>
#include <tob/ebpf/llvm_utils.h>

namespace tob::ebpf {

namespace {

// Name prefix for bitfield storages
const std::string kBitfieldStorageNamePrefix{"__llvmbridge_bitfield_storage"};

// Name prefix for padding structure members
const std::string kPaddingFieldNamePrefix{"__llvmbridge_padding"};

// Name of the custom BTF type used for padding
const std::string kInternalByteTypeName{"__llvmbridge_u8"};

// Importer callbacks
const std::unordered_map<BTFKind, std::optional<LLVMBridgeError> (*)(
                                      LLVMBridge::Context &, llvm::Module &,
                                      std::uint32_t, const BTFType &)>
    kBTFTypeImporterMap = {
        {BTFKind::Void, LLVMBridge::skipType},
        {BTFKind::Int, LLVMBridge::importIntType},
        {BTFKind::Ptr, LLVMBridge::importPtrType},
        {BTFKind::Array, LLVMBridge::importArrayType},
        {BTFKind::Struct, LLVMBridge::importStructType},
        {BTFKind::Union, LLVMBridge::importUnionType},
        {BTFKind::Enum, LLVMBridge::importEnumType},
        {BTFKind::Fwd, LLVMBridge::importFwdType},
        {BTFKind::Typedef, LLVMBridge::importTypedefType},
        {BTFKind::Volatile, LLVMBridge::importVolatileType},
        {BTFKind::Const, LLVMBridge::importConstType},
        {BTFKind::Restrict, LLVMBridge::importRestrictType},
        {BTFKind::Func, LLVMBridge::skipType},
        {BTFKind::FuncProto, LLVMBridge::importFuncProtoType},
        {BTFKind::Var, LLVMBridge::skipType},
        {BTFKind::DataSec, LLVMBridge::skipType},
        {BTFKind::Float, LLVMBridge::importFloatType},
};

} // namespace

const std::uint32_t LLVMBridge::kInternalByteTypeID{0xFFFFFFFF - 1};
const std::uint32_t LLVMBridge::kInitialCustomBTFTypeID{kInternalByteTypeID -
                                                        1};

LLVMBridge::LLVMBridge(llvm::Module &module, const IBTF &btf)
    : d(new Context(module)) {

  d->btf_type_map = btf.getAll();

  initializeInternalTypes(*d.get());
  auto opt_error = preprocessTypes(*d.get());
  if (opt_error.has_value()) {
    throw opt_error.value();
  }

  opt_error = importAllTypes();
  if (opt_error.has_value()) {
    throw opt_error.value();
  }
}

LLVMBridge::~LLVMBridge() {}

Result<llvm::Type *, LLVMBridgeError>
LLVMBridge::getType(const std::string &name) const {
  return getType(*d.get(), name);
}

void LLVMBridge::initializeInternalTypes(Context &context) {
  IntBTFType byte_type;
  byte_type.name = kInternalByteTypeName;
  byte_type.size = 1;
  byte_type.encoding = IntBTFType::Encoding::None;
  byte_type.offset = 0;
  byte_type.bits = 8;

  context.btf_type_map.insert({kInternalByteTypeID, std::move(byte_type)});
}

std::optional<LLVMBridgeError> LLVMBridge::preprocessTypes(Context &context) {
  for (const auto &p : context.btf_type_map) {
    auto btf_id = p.first;
    const auto &btf_type = p.second;

    std::optional<LLVMBridgeError> opt_error;

    if (IBTF::getBTFTypeKind(btf_type) == BTFKind::Struct) {
      const auto &struct_type = std::get<StructBTFType>(btf_type);
      opt_error = preprocessStructureType(context, struct_type, btf_id);

    } else if (IBTF::getBTFTypeKind(btf_type) == BTFKind::Union) {
      const auto &union_type = std::get<UnionBTFType>(btf_type);
      opt_error = preprocessUnionType(context, union_type, btf_id);
    }

    if (opt_error.has_value()) {
      throw opt_error.value();
    }
  }

  return std::nullopt;
}

bool LLVMBridge::isBitfield(const StructBTFType::Member &member) {
  return (member.opt_bitfield_size.has_value() &&
          member.opt_bitfield_size.value() != 0);
}

bool LLVMBridge::expandBitfield(StructBTFType::Member &destination,
                                const StructBTFType::Member &bitfield) {
  if (!isBitfield(destination) || !isBitfield(bitfield)) {
    return false;
  }

  auto destination_size = destination.opt_bitfield_size.value();
  auto expected_offset = destination.offset + destination_size;
  if (bitfield.offset != expected_offset) {
    return false;
  }

  destination_size += bitfield.opt_bitfield_size.value();
  destination.opt_bitfield_size = destination_size;

  return true;
}

std::optional<LLVMBridgeError> LLVMBridge::preprocessStructureType(
    Context &context, const StructBTFType &struct_type, std::uint32_t btf_id) {
  std::uint32_t current_offset{0};

  StructBTFType new_struct_type = struct_type;
  new_struct_type.member_list.clear();

  StructMapping struct_mapping;

  std::optional<StructBTFType::Member> opt_current_bitfield;
  std::uint32_t bitfield_storage_name_generator{};
  std::uint32_t padding_name_generator{};

  for (auto member_it = struct_type.member_list.begin();
       member_it != struct_type.member_list.end(); ++member_it) {

    const auto &member = *member_it;
    if (current_offset > member.offset) {
      return LLVMBridgeError(LLVMBridgeErrorCode::InvalidStructureMemberOffset);
    }

    auto padding_bit_count = member.offset - current_offset;

    if (isBitfield(member)) {
      if (!opt_current_bitfield.has_value()) {
        // New bitfield
        auto current_bitfield = member;

        current_bitfield.opt_name =
            kBitfieldStorageNamePrefix +
            std::to_string(bitfield_storage_name_generator);

        ++bitfield_storage_name_generator;

        // Adjust the bitfield if it does not start at relative offset 0
        if (padding_bit_count != 0) {
          current_bitfield.offset -= padding_bit_count;

          auto new_bitfield_size =
              current_bitfield.opt_bitfield_size.value() + padding_bit_count;

          current_bitfield.opt_bitfield_size = new_bitfield_size;
        }

        opt_current_bitfield = std::move(current_bitfield);

      } else {
        // A new part of an existing bitfield
        auto bitfield = member;

        // Adjust the bitfield if there's a hole between the previous one and
        // the current one
        if (padding_bit_count != 0) {
          bitfield.offset -= padding_bit_count;

          auto new_bitfield_size =
              bitfield.opt_bitfield_size.value() + padding_bit_count;

          bitfield.opt_bitfield_size = new_bitfield_size;
        }

        auto &current_bitfield = opt_current_bitfield.value();
        if (!expandBitfield(current_bitfield, bitfield)) {
          return LLVMBridgeError(LLVMBridgeErrorCode::BitfieldError);
        }
      }

      const auto &current_bitfield = opt_current_bitfield.value();
      current_offset =
          current_bitfield.offset + current_bitfield.opt_bitfield_size.value();

      StructFieldMapping mapping;
      mapping.opt_name = member.opt_name;
      mapping.type = member.type;
      mapping.as_union = false;
      mapping.index =
          static_cast<std::uint32_t>(new_struct_type.member_list.size());

      StructFieldMapping::Mask mask;
      mask.bit_offset = member.offset - current_bitfield.offset;
      mask.bit_size = member.opt_bitfield_size.value();
      mapping.opt_mask = std::move(mask);

      struct_mapping.push_back(std::move(mapping));

    } else {
      // Close the active bitfield, if any
      if (opt_current_bitfield.has_value()) {
        auto &current_bitfield = opt_current_bitfield.value();

        if ((padding_bit_count % 8) != 0) {
          auto aligned_bitfield_size = static_cast<std::uint32_t>(
              current_bitfield.opt_bitfield_size.value() / 8);
          if ((current_bitfield.opt_bitfield_size.value() % 8) != 0) {
            ++aligned_bitfield_size;
          }

          aligned_bitfield_size *= 8;

          current_bitfield.opt_bitfield_size = aligned_bitfield_size;
          current_offset = current_bitfield.offset + aligned_bitfield_size;

          padding_bit_count = member.offset - current_offset;
        }

        new_struct_type.member_list.push_back(std::move(current_bitfield));

        opt_current_bitfield = std::nullopt;
      }

      if (padding_bit_count != 0) {
        if ((padding_bit_count % 8) != 0) {
          return LLVMBridgeError(
              LLVMBridgeErrorCode::InvalidStructureMemberOffset);
        }

        auto padding_byte_count = padding_bit_count / 8;

        auto padding = generatePaddingStructMember(context, padding_byte_count,
                                                   current_offset);

        padding.opt_name =
            kPaddingFieldNamePrefix + std::to_string(padding_name_generator);

        ++padding_name_generator;

        new_struct_type.member_list.push_back(padding);
        current_offset += padding_bit_count;
      }

      auto opt_type_size = getBTFTypeSize(context, member.type);
      if (!opt_type_size.has_value()) {
        return LLVMBridgeError(LLVMBridgeErrorCode::UnsupportedBTFType);
      }

      auto type_size = opt_type_size.value();
      current_offset += type_size;

      StructFieldMapping mapping;
      mapping.opt_name = member.opt_name;
      mapping.type = member.type;
      mapping.as_union = false;
      mapping.index =
          static_cast<std::uint32_t>(new_struct_type.member_list.size());

      struct_mapping.push_back(std::move(mapping));

      new_struct_type.member_list.push_back(member);
    }
  }

  auto padding_bit_count = (struct_type.size * 8) - current_offset;

  // Close any pending bitfield, if any
  if (opt_current_bitfield.has_value()) {
    auto current_bitfield = opt_current_bitfield.value();
    opt_current_bitfield = std::nullopt;

    if ((padding_bit_count % 8) != 0) {
      auto aligned_bitfield_size = static_cast<std::uint32_t>(
          current_bitfield.opt_bitfield_size.value() / 8);
      if ((current_bitfield.opt_bitfield_size.value() % 8) != 0) {
        ++aligned_bitfield_size;
      }

      aligned_bitfield_size *= 8;

      current_bitfield.opt_bitfield_size = aligned_bitfield_size;
      current_offset = current_bitfield.offset + aligned_bitfield_size;

      padding_bit_count = (struct_type.size * 8) - current_offset;
    }

    new_struct_type.member_list.push_back(std::move(current_bitfield));
  }

  if (padding_bit_count != 0) {
    if ((padding_bit_count % 8) != 0) {
      return LLVMBridgeError(LLVMBridgeErrorCode::InvalidStructureMemberOffset);
    }

    auto padding_byte_count = padding_bit_count / 8;
    auto padding = generatePaddingStructMember(context, padding_byte_count,
                                               current_offset);

    padding.opt_name =
        kPaddingFieldNamePrefix + std::to_string(padding_name_generator);
    ++padding_name_generator;

    new_struct_type.member_list.push_back(padding);
    current_offset += padding_bit_count;
  }

  if (current_offset != (struct_type.size * 8)) {
    return LLVMBridgeError(LLVMBridgeErrorCode::InvalidStructSize);
  }

  context.btf_type_map[btf_id] = std::move(new_struct_type);
  context.btf_struct_mapping.insert({btf_id, struct_mapping});

  return std::nullopt;
}

std::optional<LLVMBridgeError> LLVMBridge::preprocessUnionType(
    Context &context, const UnionBTFType &union_type, std::uint32_t btf_id) {
  StructMapping struct_mapping;

  for (const auto &member : union_type.member_list) {
    auto is_bitfield = (member.opt_bitfield_size.has_value() &&
                        member.opt_bitfield_size.value() != 0);
    if (is_bitfield) {
      return LLVMBridgeError(LLVMBridgeErrorCode::UnsupportedBTFType);
    }

    StructFieldMapping mapping = {};

    mapping.opt_name = member.opt_name;
    mapping.type = member.type;
    mapping.as_union = true;
    mapping.index = 0;

    struct_mapping.push_back(std::move(mapping));
  }

  context.btf_struct_mapping.insert({btf_id, struct_mapping});
  return std::nullopt;
}

Result<LLVMBridge::ElementPtr, LLVMBridgeError>
LLVMBridge::getElementPtr(Context &context, llvm::IRBuilder<> &builder,
                          llvm::Value *opaque_pointer, llvm::Type *pointer_type,
                          std::uint32_t pointer_btf_type_id,
                          const std::string &path, llvm::Value *temp_storage,
                          llvm::BasicBlock *read_failed_bb) {
  opaque_pointer = builder.CreateBitOrPointerCast(opaque_pointer,
                                                  pointer_type->getPointerTo());

  auto syscall_interface_exp = BPFSyscallInterface::create(builder);
  if (!syscall_interface_exp.succeeded()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::InternalError);
  }

  auto syscall_interface = syscall_interface_exp.takeValue();

  auto current_bb = builder.GetInsertBlock();
  auto function = current_bb->getParent();

  auto &module = *current_bb->getModule();
  auto &llvm_context = module.getContext();

  auto opt_path_component_list = parsePath(path);
  if (!opt_path_component_list.has_value()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::InvalidPath);
  }

  const auto &path_component_list = opt_path_component_list.value();

  for (auto path_comp_it = path_component_list.begin();
       path_comp_it != path_component_list.end(); ++path_comp_it) {

    const auto &path_component = *path_comp_it;

    auto is_last_path_comp =
        std::next(path_comp_it, 1) == path_component_list.end();

    if (!path_component.name.empty()) {
      auto opt_structure_mapping =
          locate(context, pointer_btf_type_id, path_component.name);

      if (!opt_structure_mapping.has_value()) {
        return LLVMBridgeError(LLVMBridgeErrorCode::InvalidPath);
      }

      const auto &structure_mapping = opt_structure_mapping.value();

      for (auto mapping_it = structure_mapping.begin();
           mapping_it != structure_mapping.end(); ++mapping_it) {

        const auto &mapping = *mapping_it;

        opaque_pointer = builder.CreateGEP(
            pointer_type, opaque_pointer,
            {builder.getInt32(0), builder.getInt32(mapping.index)});

        pointer_btf_type_id = mapping.type;
        pointer_type = context.btf_type_id_to_llvm.at(pointer_btf_type_id);

        if (structure_mapping.back().opt_mask.has_value()) {
          auto is_last_mapping =
              std::next(mapping_it, 1) == structure_mapping.end();

          if (!is_last_path_comp || !is_last_mapping) {
            return LLVMBridgeError(LLVMBridgeErrorCode::InvalidPath);
          }
        }
      }
    }

    // Arrays
    if (!path_component.index_list.empty()) {
      auto btf_type_it = context.btf_type_map.find(pointer_btf_type_id);
      if (btf_type_it == context.btf_type_map.end()) {
        return LLVMBridgeError(LLVMBridgeErrorCode::InvalidPath);
      }

      const auto &btf_type = btf_type_it->second;
      if (std::holds_alternative<btfparse::PtrBTFType>(btf_type)) {
        // Dereference this pointer so that we get to the array itself
        const auto &ptr_btf_type = std::get<btfparse::PtrBTFType>(btf_type);

        if (temp_storage == nullptr) {
          return LLVMBridgeError(LLVMBridgeErrorCode::TempStorageRequired);
        }

        auto read_status = syscall_interface->probeRead(
            temp_storage, builder.getInt64(sizeof(void *)), opaque_pointer);

        auto cond = builder.CreateICmpEQ(builder.getInt64(0U), read_status);

        auto read_succeeded_bb =
            llvm::BasicBlock::Create(llvm_context, "read_succeeded", function);

        if (read_failed_bb == nullptr) {
          read_failed_bb =
              llvm::BasicBlock::Create(llvm_context, "read_failed", function);

          builder.SetInsertPoint(read_failed_bb);
          builder.CreateRet(builder.getInt64(0));

          builder.SetInsertPoint(current_bb);
        }

        builder.CreateCondBr(cond, read_succeeded_bb, read_failed_bb);
        builder.SetInsertPoint(read_succeeded_bb);

        opaque_pointer = builder.CreateLoad(pointer_type, temp_storage);
        pointer_btf_type_id = ptr_btf_type.type;
        pointer_type = context.btf_type_id_to_llvm.at(ptr_btf_type.type);

        opaque_pointer = builder.CreateBitOrPointerCast(
            opaque_pointer, pointer_type->getPointerTo());
      }

      std::vector<llvm::Value *> index_list = {builder.getInt32(0)};
      for (const auto &index : path_component.index_list) {
        index_list.push_back(builder.getInt32(index));
      }

      opaque_pointer =
          builder.CreateGEP(pointer_type, opaque_pointer, index_list);

      const auto &array_btf_type = std::get<btfparse::ArrayBTFType>(btf_type);
      pointer_btf_type_id = array_btf_type.type;
      pointer_type = context.btf_type_id_to_llvm.at(pointer_btf_type_id);
    }

    // This may be a pointer again; dereference it if we still have other
    // path components to handle
    if (!is_last_path_comp) {
      auto btf_type_it = context.btf_type_map.find(pointer_btf_type_id);
      if (btf_type_it == context.btf_type_map.end()) {
        return LLVMBridgeError(LLVMBridgeErrorCode::InvalidPath);
      }

      const auto &btf_type = btf_type_it->second;
      if (std::holds_alternative<btfparse::PtrBTFType>(btf_type)) {
        const auto &ptr_btf_type = std::get<btfparse::PtrBTFType>(btf_type);

        if (temp_storage == nullptr) {
          return LLVMBridgeError(LLVMBridgeErrorCode::TempStorageRequired);
        }

        auto read_status = syscall_interface->probeRead(
            temp_storage, builder.getInt64(sizeof(void *)), opaque_pointer);

        auto cond = builder.CreateICmpEQ(builder.getInt64(0U), read_status);

        auto read_succeeded_bb =
            llvm::BasicBlock::Create(llvm_context, "read_succeeded", function);

        if (read_failed_bb == nullptr) {
          read_failed_bb =
              llvm::BasicBlock::Create(llvm_context, "read_failed", function);

          builder.SetInsertPoint(read_failed_bb);
          builder.CreateRet(builder.getInt64(0));

          builder.SetInsertPoint(current_bb);
        }

        builder.CreateCondBr(cond, read_succeeded_bb, read_failed_bb);
        builder.SetInsertPoint(read_succeeded_bb);

        opaque_pointer = builder.CreateLoad(pointer_type, temp_storage);
        pointer_btf_type_id = ptr_btf_type.type;
        pointer_type = context.btf_type_id_to_llvm.at(ptr_btf_type.type);

        opaque_pointer = builder.CreateBitOrPointerCast(
            opaque_pointer, pointer_type->getPointerTo());
      }
    }
  }

  return ElementPtr{pointer_btf_type_id, pointer_type, opaque_pointer};
}

std::optional<LLVMBridge::PathComponentList>
LLVMBridge::parsePath(const std::string &path) {

  std::vector<std::string> string_list;
  std::size_t start{};

  while (start < path.size()) {
    auto end = path.find_first_of('.', start);
    if (end == std::string::npos) {
      end = path.size();
    }

    auto str = path.substr(start, end - start);
    string_list.push_back(std::move(str));

    start = end + 1;
  }

  PathComponentList path_component_list;

  for (const auto &str : string_list) {
    auto start_index = str.find('[');

    PathComponent path_component;
    path_component.name = str.substr(0, start_index);

    if (start_index != std::string::npos) {
      bool inside_bracket{false};
      std::string current_index;

      for (std::size_t i{start_index}; i < str.size(); ++i) {
        const auto &current_char = str[i];

        if (current_char == '[') {
          if (inside_bracket) {
            return std::nullopt;
          }

          inside_bracket = true;

        } else if (current_char == ']') {
          if (!inside_bracket) {
            return std::nullopt;
          }

          inside_bracket = false;

          if (current_index.empty()) {
            return std::nullopt;
          }

          char *terminator_ptr{nullptr};
          auto index = static_cast<std::uint32_t>(
              std::strtoul(current_index.data(), &terminator_ptr, 10));

          if (terminator_ptr != nullptr && *terminator_ptr != '\0') {
            return std::nullopt;
          }

          path_component.index_list.push_back(index);
          current_index.clear();

        } else if (std::isdigit(current_char)) {
          current_index.push_back(current_char);

        } else {
          return std::nullopt;
        }
      }
    }

    for (const auto &c : path_component.name) {
      if (!std::isalnum(c) && c != '_') {
        return std::nullopt;
      }
    }

    path_component_list.push_back(std::move(path_component));
    path_component = {};
  }

  if (path_component_list.empty()) {
    return std::nullopt;
  }

  return path_component_list;
}

std::optional<LLVMBridge::StructMapping>
LLVMBridge::locateHelper(const LLVMBridge::Context &context,
                         LLVMBridge::StructMapping output_mapping,
                         std::uint32_t btf_type_id,
                         const std::string &component) {
  auto struct_mapping_it = context.btf_struct_mapping.find(btf_type_id);
  if (struct_mapping_it == context.btf_struct_mapping.end()) {
    return std::nullopt;
  }

  const auto &struct_mapping = struct_mapping_it->second;

  auto member_it =
      std::find_if(struct_mapping.begin(), struct_mapping.end(),
                   [&component](const StructFieldMapping &mapping) -> bool {
                     if (!mapping.opt_name.has_value()) {
                       return false;
                     }

                     const auto &mapping_name = mapping.opt_name.value();
                     return mapping_name == component;
                   });

  if (member_it != struct_mapping.end()) {
    const auto &mapping = *member_it;

    auto new_output_mapping = output_mapping;
    new_output_mapping.push_back(mapping);

    return new_output_mapping;
  }

  for (const auto &mapping : struct_mapping) {
    if (mapping.opt_name.has_value()) {
      continue;
    }

    auto new_output_mapping = output_mapping;
    new_output_mapping.push_back(mapping);

    auto opt_mapping =
        locateHelper(context, new_output_mapping, mapping.type, component);

    if (opt_mapping.has_value()) {
      return opt_mapping;
    }
  }

  return std::nullopt;
}

std::optional<LLVMBridge::StructMapping>
LLVMBridge::locate(const LLVMBridge::Context &context,
                   std::uint32_t btf_type_id, const std::string &component) {
  return locateHelper(context, {}, btf_type_id, component);
}

std::optional<std::uint32_t>
LLVMBridge::getBTFTypeSize(const LLVMBridge::Context &context,
                           const BTFType &type) {

  switch (IBTF::getBTFTypeKind(type)) {
  case BTFKind::Void: {
    return std::nullopt;
  }

  case BTFKind::Int: {
    const auto &btf_type = std::get<IntBTFType>(type);
    return btf_type.size * 8;
  }

  case BTFKind::Ptr: {
    return sizeof(void *) * 8;
  }

  case BTFKind::Array: {
    const auto &btf_type = std::get<ArrayBTFType>(type);

    auto opt_elem_size = getBTFTypeSize(context, btf_type.type);
    if (!opt_elem_size.has_value()) {
      return opt_elem_size;
    }

    return opt_elem_size.value() * btf_type.nelems;
  }

  case BTFKind::Struct: {
    const auto &btf_type = std::get<StructBTFType>(type);
    return btf_type.size * 8;
  }

  case BTFKind::Union: {
    const auto &btf_type = std::get<UnionBTFType>(type);
    return btf_type.size * 8;
  }

  case BTFKind::Enum: {
    const auto &btf_type = std::get<EnumBTFType>(type);
    return btf_type.size * 8;
  }

  case BTFKind::Fwd: {
    return std::nullopt;
  }

  case BTFKind::Typedef: {
    const auto &btf_type = std::get<TypedefBTFType>(type);
    return getBTFTypeSize(context, btf_type.type);
  }

  case BTFKind::Volatile: {
    const auto &btf_type = std::get<VolatileBTFType>(type);
    return getBTFTypeSize(context, btf_type.type);
  }

  case BTFKind::Const: {
    const auto &btf_type = std::get<ConstBTFType>(type);
    return getBTFTypeSize(context, btf_type.type);
  }

  case BTFKind::Restrict: {
    return std::nullopt;
  }

  case BTFKind::Func: {
    return std::nullopt;
  }

  case BTFKind::FuncProto: {
    return std::nullopt;
  }

  case BTFKind::Var: {
    return std::nullopt;
  }

  case BTFKind::DataSec: {
    return std::nullopt;
  }

  case BTFKind::Float: {
    const auto &btf_type = std::get<FloatBTFType>(type);
    return btf_type.size * 8;
  }
  }

  return 0;
}

std::optional<std::uint32_t>
LLVMBridge::getBTFTypeSize(const LLVMBridge::Context &context,
                           std::uint32_t type) {

  auto type_it = context.btf_type_map.find(type);
  if (type_it == context.btf_type_map.end()) {
    return std::nullopt;
  }

  return getBTFTypeSize(context, type_it->second);
}

std::uint32_t LLVMBridge::generatePaddingBTFArrayType(Context &context,
                                                      std::uint32_t size) {
  ArrayBTFType array_type;
  array_type.type = kInternalByteTypeID;
  array_type.index_type = kInternalByteTypeID;
  array_type.nelems = size;

  ++context.btf_type_id_generator;

  auto id = kInitialCustomBTFTypeID - context.btf_type_id_generator;
  context.btf_type_map.insert({id, std::move(array_type)});

  return id;
}

StructBTFType::Member
LLVMBridge::generatePaddingStructMember(Context &context, std::uint32_t size,
                                        std::uint32_t offset) {

  StructBTFType::Member padding;

  padding.type = generatePaddingBTFArrayType(context, size);
  padding.offset = offset;

  return padding;
}

Result<LLVMBridge::ElementPtr, LLVMBridgeError>
LLVMBridge::getElementPtr(llvm::IRBuilder<> &builder,
                          llvm::Value *opaque_pointer, llvm::Type *pointer_type,
                          const std::string &path, llvm::Value *temp_storage,
                          llvm::BasicBlock *read_failed_bb) const {

  auto btf_type_id_it = d->llvm_to_btf_type_id.find(pointer_type);
  if (btf_type_id_it == d->llvm_to_btf_type_id.end()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::UnsupportedBTFType);
  }

  auto btf_type_id = btf_type_id_it->second;
  return getElementPtr(*d.get(), builder, opaque_pointer, pointer_type,
                       btf_type_id, path, temp_storage, read_failed_bb);
}

Result<LLVMBridge::ElementPtr, LLVMBridgeError> LLVMBridge::getElementPtr(
    llvm::IRBuilder<> &builder, llvm::Value *opaque_pointer,
    const std::string &pointer_type_name, const std::string &path,
    llvm::Value *temp_storage, llvm::BasicBlock *read_failed_bb) const {

  auto btf_type_id_it = d->name_to_btf_type_id.find(pointer_type_name);
  if (btf_type_id_it == d->name_to_btf_type_id.end()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::UnsupportedBTFType);
  }

  auto btf_type_id = btf_type_id_it->second;

  auto pointer_type_it = d->btf_type_id_to_llvm.find(btf_type_id);
  if (pointer_type_it == d->btf_type_id_to_llvm.end()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::UnsupportedBTFType);
  }

  auto pointer_type = pointer_type_it->second;

  return getElementPtr(*d.get(), builder, opaque_pointer, pointer_type,
                       btf_type_id, path, temp_storage, read_failed_bb);
}

std::optional<LLVMBridgeError> LLVMBridge::importAllTypes() {
  // Initialize the type queue
  std::vector<std::uint32_t> next_id_queue(d->btf_type_map.size());

  std::size_t i{};
  for (const auto &btf_type_p : d->btf_type_map) {
    next_id_queue[i] = btf_type_p.first;
    ++i;
  }

  // BTF id 0 is never defined, and is interpreted as the `void` type
  auto &llvm_context = d->module.getContext();
  auto void_type = llvm::Type::getVoidTy(llvm_context);

  d->btf_type_id_to_llvm.insert({0, void_type});
  d->llvm_to_btf_type_id.insert({void_type, 0});

  // Attempt to import types in a loop until there are no new updates
  while (!next_id_queue.empty()) {
    auto current_id_queue = std::move(next_id_queue);
    next_id_queue.clear();

    bool updated{false};

    for (const auto &id : current_id_queue) {
      const auto &btf_type = d->btf_type_map.at(id);

      // In case we fail with a `MissingDependency` error, put this
      // type back into the queue so that we'll try again to import it
      // later
      auto opt_error = importType(id, btf_type);
      if (opt_error.has_value()) {
        auto error = opt_error.value();
        if (error.get() != LLVMBridgeErrorCode::MissingDependency) {
          return error;
        }

        next_id_queue.push_back(id);

      } else {
        updated = true;
      }
    }

    if (!updated) {
      break;
    }
  }

  // If the next queue is not empty, we have failed to import one or
  // more types
  if (!next_id_queue.empty()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::MissingDependency);
  }

  return std::nullopt;
}

std::optional<LLVMBridgeError> LLVMBridge::importType(std::uint32_t id,
                                                      const BTFType &type) {
  auto importer_it = kBTFTypeImporterMap.find(IBTF::getBTFTypeKind(type));
  if (importer_it == kBTFTypeImporterMap.end()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::UnsupportedBTFType);
  }

  const auto &importer = importer_it->second;
  return importer(*d.get(), d->module, id, type);
}

Result<llvm::Type *, LLVMBridgeError>
LLVMBridge::getType(const Context &context, const std::string &name) {
  auto btf_type_id_it = context.name_to_btf_type_id.find(name);
  if (btf_type_id_it == context.name_to_btf_type_id.end()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::NotFound);
  }

  auto btf_type_id = btf_type_id_it->second;

  auto llvm_type_it = context.btf_type_id_to_llvm.find(btf_type_id);
  if (llvm_type_it == context.btf_type_id_to_llvm.end()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::TypeIsNotIndexed);
  }

  return llvm_type_it->second;
}

llvm::StructType *LLVMBridge::getOrCreateOpaqueStruct(
    Context &context, llvm::Module &module, std::uint32_t id,
    const std::optional<std::string> &opt_name) {
  llvm::StructType *llvm_struct_type{nullptr};

  auto llvm_type_it = context.btf_type_id_to_llvm.find(id);
  if (llvm_type_it != context.btf_type_id_to_llvm.end()) {
    llvm_struct_type = static_cast<llvm::StructType *>(llvm_type_it->second);

  } else {
    auto &llvm_context = module.getContext();

    if (opt_name.has_value()) {
      llvm_struct_type =
          llvm::StructType::create(llvm_context, opt_name.value());
    } else {
      llvm_struct_type = llvm::StructType::create(llvm_context);
    }

    saveType(context, id, llvm_struct_type, opt_name);
  }

  return llvm_struct_type;
}

void LLVMBridge::saveType(Context &context, std::uint32_t id, llvm::Type *type,
                          const std::optional<std::string> &opt_name) {
  context.btf_type_id_to_llvm.insert({id, type});
  context.llvm_to_btf_type_id.insert({type, id});

  if (opt_name.has_value()) {
    const auto &name = opt_name.value();

    if (context.blocked_type_name_list.count(name) != 0) {
      return;
    }

    if (context.name_to_btf_type_id.count(name) > 0) {
      context.blocked_type_name_list.insert(name);
      context.name_to_btf_type_id.erase(name);

    } else {
      context.name_to_btf_type_id.insert({name, id});
    }
  }
}

std::optional<LLVMBridgeError> LLVMBridge::skipType(Context &, llvm::Module &,
                                                    std::uint32_t,
                                                    const BTFType &) {
  return std::nullopt;
}

std::optional<LLVMBridgeError> LLVMBridge::importIntType(Context &context,
                                                         llvm::Module &module,
                                                         std::uint32_t id,
                                                         const BTFType &type) {
  if (context.btf_type_id_to_llvm.count(id) > 0) {
    return std::nullopt;
  }

  auto &llvm_context = module.getContext();
  llvm::Type *llvm_type{nullptr};

  const auto &int_type = std::get<IntBTFType>(type);
  switch (int_type.size) {
  case 1:
    llvm_type = llvm::Type::getInt8Ty(llvm_context);
    break;

  case 2:
    llvm_type = llvm::Type::getInt16Ty(llvm_context);
    break;

  case 4:
    llvm_type = llvm::Type::getInt32Ty(llvm_context);
    break;

  case 8:
    llvm_type = llvm::Type::getInt64Ty(llvm_context);
    break;

  case 16:
    llvm_type = llvm::Type::getInt128Ty(llvm_context);
    break;

  default:
    return LLVMBridgeError(LLVMBridgeErrorCode::UnsupportedBTFType);
  }

  saveType(context, id, llvm_type, std::nullopt);
  return std::nullopt;
}

std::optional<LLVMBridgeError> LLVMBridge::importPtrType(Context &context,
                                                         llvm::Module &,
                                                         std::uint32_t id,
                                                         const BTFType &type) {
  if (context.btf_type_id_to_llvm.count(id) > 0) {
    return std::nullopt;
  }

  const auto &ptr_type = std::get<PtrBTFType>(type);

  auto llvm_type_it = context.btf_type_id_to_llvm.find(ptr_type.type);
  if (llvm_type_it == context.btf_type_id_to_llvm.end()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::MissingDependency);
  }

  auto base_llvm_type = llvm_type_it->second;
  auto llvm_type = base_llvm_type->getPointerTo();

  saveType(context, id, llvm_type, std::nullopt);
  return std::nullopt;
}

std::optional<LLVMBridgeError>
LLVMBridge::importArrayType(Context &context, llvm::Module &module,
                            std::uint32_t id, const BTFType &type) {
  if (context.btf_type_id_to_llvm.count(id) > 0) {
    return std::nullopt;
  }

  const auto &array_type = std::get<ArrayBTFType>(type);

  auto llvm_elem_type_it = context.btf_type_id_to_llvm.find(array_type.type);
  if (llvm_elem_type_it == context.btf_type_id_to_llvm.end()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::MissingDependency);
  }

  auto llvm_elem_type = llvm_elem_type_it->second;
  auto llvm_type = llvm::ArrayType::get(llvm_elem_type, array_type.nelems);

  saveType(context, id, llvm_type, std::nullopt);
  return std::nullopt;
}

std::optional<LLVMBridgeError>
LLVMBridge::importStructType(Context &context, llvm::Module &module,
                             std::uint32_t id, const BTFType &type) {
  auto struct_type = std::get<StructBTFType>(type);

  auto llvm_struct_type =
      getOrCreateOpaqueStruct(context, module, id, struct_type.opt_name);

  if (!llvm_struct_type->isOpaque()) {
    return std::nullopt;
  }

  auto llvm_byte_type = llvm::Type::getInt8Ty(module.getContext());

  std::vector<llvm::Type *> member_type_list;
  std::uint32_t current_offset{};

  std::size_t index{};

  for (const auto &struct_member : struct_type.member_list) {
    if (struct_member.offset != current_offset) {
      return LLVMBridgeError(LLVMBridgeErrorCode::InvalidStructureMemberOffset);
    }

    llvm::Type *member_type{nullptr};

    if (isBitfield(struct_member)) {
      auto bitfield_size = struct_member.opt_bitfield_size.value();

      auto byte_size = static_cast<std::uint32_t>(bitfield_size / 8);
      if ((bitfield_size % 8) != 0) {
        ++byte_size;
      }

      member_type = llvm::ArrayType::get(llvm_byte_type, byte_size);

    } else {
      auto member_type_it =
          context.btf_type_id_to_llvm.find(struct_member.type);

      if (member_type_it == context.btf_type_id_to_llvm.end()) {
        return LLVMBridgeError(LLVMBridgeErrorCode::MissingDependency);
      }

      member_type = member_type_it->second;
      if (!member_type->isSized()) {
        return LLVMBridgeError(LLVMBridgeErrorCode::MissingDependency);
      }
    }

    member_type_list.push_back(member_type);

    auto byte_size =
        static_cast<std::uint32_t>(getTypeSize(module, member_type));

    current_offset += byte_size * 8;

    ++index;
  }

  llvm_struct_type->setBody(member_type_list, true);

  auto struct_size =
      static_cast<std::uint32_t>(getTypeSize(module, llvm_struct_type));

  if (struct_size != struct_type.size) {
    return LLVMBridgeError(LLVMBridgeErrorCode::InvalidStructSize);
  }

  return std::nullopt;
}

std::optional<LLVMBridgeError>
LLVMBridge::importUnionType(Context &context, llvm::Module &module,
                            std::uint32_t id, const BTFType &type) {
  const auto &union_type = std::get<UnionBTFType>(type);

  auto llvm_struct_type =
      getOrCreateOpaqueStruct(context, module, id, union_type.opt_name);

  if (!llvm_struct_type->isOpaque()) {
    return std::nullopt;
  }

  auto &llvm_context = module.getContext();
  auto byte_type = llvm::Type::getInt8Ty(llvm_context);

  std::vector<llvm::Type *> llvm_type_list{
      llvm::ArrayType::get(byte_type, union_type.size)};

  llvm_struct_type->setBody(llvm_type_list, true);
  return std::nullopt;
}

std::optional<LLVMBridgeError> LLVMBridge::importEnumType(Context &context,
                                                          llvm::Module &module,
                                                          std::uint32_t id,
                                                          const BTFType &type) {
  if (context.btf_type_id_to_llvm.count(id) > 0) {
    return std::nullopt;
  }

  auto &llvm_context = module.getContext();
  const auto &enum_type = std::get<EnumBTFType>(type);

  llvm::Type *llvm_type{nullptr};

  switch (enum_type.size) {
  case 1:
    llvm_type = llvm::Type::getInt8Ty(llvm_context);
    break;

  case 2:
    llvm_type = llvm::Type::getInt16Ty(llvm_context);
    break;

  case 4:
    llvm_type = llvm::Type::getInt32Ty(llvm_context);
    break;

  case 8:
    llvm_type = llvm::Type::getInt64Ty(llvm_context);
    break;

  case 16:
    llvm_type = llvm::Type::getInt128Ty(llvm_context);
    break;

  default:
    return LLVMBridgeError(LLVMBridgeErrorCode::UnsupportedBTFType);
  }

  saveType(context, id, llvm_type, std::nullopt);
  return std::nullopt;
}

std::optional<LLVMBridgeError> LLVMBridge::importFwdType(Context &context,
                                                         llvm::Module &module,
                                                         std::uint32_t id,
                                                         const BTFType &type) {
  if (context.btf_type_id_to_llvm.count(id) > 0) {
    return std::nullopt;
  }

  auto &llvm_context = module.getContext();
  auto llvm_type = llvm::StructType::get(llvm_context);

  saveType(context, id, llvm_type, std::nullopt);
  return std::nullopt;
}

std::optional<LLVMBridgeError>
LLVMBridge::importTypedefType(Context &context, llvm::Module &module,
                              std::uint32_t id, const BTFType &type) {
  if (context.btf_type_id_to_llvm.count(id) > 0) {
    return std::nullopt;
  }

  const auto &typedef_type = std::get<TypedefBTFType>(type);

  auto llvm_type_it = context.btf_type_id_to_llvm.find(typedef_type.type);
  if (llvm_type_it == context.btf_type_id_to_llvm.end()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::MissingDependency);
  }

  auto llvm_type = llvm_type_it->second;

  saveType(context, id, llvm_type, typedef_type.name);
  return std::nullopt;
}

std::optional<LLVMBridgeError>
LLVMBridge::importVolatileType(Context &context, llvm::Module &module,
                               std::uint32_t id, const BTFType &type) {
  if (context.btf_type_id_to_llvm.count(id) > 0) {
    return std::nullopt;
  }

  const auto &volatile_type = std::get<VolatileBTFType>(type);

  auto llvm_type_it = context.btf_type_id_to_llvm.find(volatile_type.type);
  if (llvm_type_it == context.btf_type_id_to_llvm.end()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::MissingDependency);
  }

  auto llvm_type = llvm_type_it->second;

  saveType(context, id, llvm_type, std::nullopt);
  return std::nullopt;
}

std::optional<LLVMBridgeError>
LLVMBridge::importRestrictType(Context &context, llvm::Module &module,
                               std::uint32_t id, const BTFType &type) {
  if (context.btf_type_id_to_llvm.count(id) > 0) {
    return std::nullopt;
  }

  const auto &restrict_type = std::get<RestrictBTFType>(type);

  auto llvm_type_it = context.btf_type_id_to_llvm.find(restrict_type.type);
  if (llvm_type_it == context.btf_type_id_to_llvm.end()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::MissingDependency);
  }

  auto llvm_type = llvm_type_it->second;

  saveType(context, id, llvm_type, std::nullopt);
  return std::nullopt;
}

std::optional<LLVMBridgeError>
LLVMBridge::importConstType(Context &context, llvm::Module &module,
                            std::uint32_t id, const BTFType &type) {
  if (context.btf_type_id_to_llvm.count(id) > 0) {
    return std::nullopt;
  }

  const auto &const_type = std::get<ConstBTFType>(type);

  auto llvm_type_it = context.btf_type_id_to_llvm.find(const_type.type);
  if (llvm_type_it == context.btf_type_id_to_llvm.end()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::MissingDependency);
  }

  auto llvm_type = llvm_type_it->second;

  saveType(context, id, llvm_type, std::nullopt);
  return std::nullopt;
}

std::optional<LLVMBridgeError>
LLVMBridge::importFuncProtoType(Context &context, llvm::Module &module,
                                std::uint32_t id, const BTFType &type) {
  if (context.btf_type_id_to_llvm.count(id) > 0) {
    return std::nullopt;
  }

  std::vector<llvm::Type *> param_type_list;

  const auto &func_proto_type = std::get<FuncProtoBTFType>(type);
  for (const auto &param : func_proto_type.param_list) {
    auto param_llvm_type_it = context.btf_type_id_to_llvm.find(param.type);
    if (param_llvm_type_it == context.btf_type_id_to_llvm.end()) {
      return LLVMBridgeError(LLVMBridgeErrorCode::MissingDependency);
    }

    auto param_llvm_type = param_llvm_type_it->second;
    param_type_list.push_back(param_llvm_type);
  }

  auto return_llvm_type_it =
      context.btf_type_id_to_llvm.find(func_proto_type.return_type);

  if (return_llvm_type_it == context.btf_type_id_to_llvm.end()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::MissingDependency);
  }

  auto return_llvm_type = return_llvm_type_it->second;

  auto llvm_type = llvm::FunctionType::get(return_llvm_type, param_type_list,
                                           func_proto_type.is_variadic);

  saveType(context, id, llvm_type, std::nullopt);
  return std::nullopt;
}

std::optional<LLVMBridgeError>
LLVMBridge::importFloatType(Context &context, llvm::Module &module,
                            std::uint32_t id, const BTFType &type) {
  if (context.btf_type_id_to_llvm.count(id) > 0) {
    return std::nullopt;
  }

  const auto &float_type = std::get<FloatBTFType>(type);

  auto &llvm_context = module.getContext();
  llvm::Type *llvm_type{nullptr};

  switch (float_type.size) {
  case 4:
    llvm_type = llvm::Type::getFloatTy(llvm_context);
    break;

  case 8:
    llvm_type = llvm::Type::getDoubleTy(llvm_context);
    break;

  default:
    return LLVMBridgeError(LLVMBridgeErrorCode::UnsupportedBTFType);
  }

  saveType(context, id, llvm_type, std::nullopt);
  return std::nullopt;
}

} // namespace tob::ebpf
