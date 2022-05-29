/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <optional>
#include <unordered_map>
#include <unordered_set>

#include <tob/ebpf/illvmbridge.h>

namespace tob::ebpf {

class LLVMBridge final : public ILLVMBridge {
public:
  /// Constructor
  LLVMBridge(llvm::Module &module, const IBTF &btf);

  /// Destructor
  virtual ~LLVMBridge();

  /// \copydoc ILLVMBridge::getType
  virtual Result<llvm::Type *, LLVMBridgeError>
  getType(const std::string &name) const override;

  /// \copydoc ILLVMBridge::getElementPtr
  virtual Result<ElementPtr, LLVMBridgeError>
  getElementPtr(llvm::IRBuilder<> &builder, llvm::Value *opaque_pointer,
                llvm::Type *pointer_type, const std::string &path,
                llvm::Value *temp_storage,
                llvm::BasicBlock *read_failed_bb) const override;

  /// \copydoc ILLVMBridge::getElementPtr
  virtual Result<ElementPtr, LLVMBridgeError>
  getElementPtr(llvm::IRBuilder<> &builder, llvm::Value *opaque_pointer,
                const std::string &pointer_type_name, const std::string &path,
                llvm::Value *temp_storage,
                llvm::BasicBlock *read_failed_bb) const override;

private:
  /// Imports all the BTF types into the active LLVM context
  std::optional<LLVMBridgeError> importAllTypes();

  /// Imports the given BTF type into the active LLVM context
  std::optional<LLVMBridgeError> importType(std::uint32_t id,
                                            const BTFType &type);

public:
  /// ID of the custom BTF type used for padding
  static const std::uint32_t kInternalByteTypeID;

  /// BTF ID generator, used to create padding types
  static const std::uint32_t kInitialCustomBTFTypeID;

  /// A single component of a broken down path
  struct PathComponent final {
    /// The name of this path component
    std::string name;

    /// A list of indexes parsed by a C-style structure qualifier
    std::vector<std::uint32_t> index_list;
  };

  /// A list of broken down path components
  using PathComponentList = std::vector<PathComponent>;

  /// Maps a single member variable to a structure index
  struct StructFieldMapping final {
    /// A mask used to extract the value, used for bitfields
    struct Mask final {
      /// A bit offset into the bitfield
      std::uint32_t bit_offset{};

      /// The value size, in bits
      std::uint32_t bit_size{};
    };

    /// An optional mask, used for bitfields
    using OptionalMask = std::optional<Mask>;

    /// Member name
    std::optional<std::string> opt_name;

    /// BTF type
    std::uint32_t type{};

    /// Member index
    std::uint32_t index{};

    /// Address this member as part of a union
    bool as_union{false};

    /// An optional mask, used for bitfields
    OptionalMask opt_mask;
  };

  /// Maps names to structure parts
  using StructMapping = std::vector<StructFieldMapping>;

  /// Internal state data
  struct Context final {
    Context(llvm::Module &module_) : module(module_) {}

    /// All the BTF types that have been either imported or generated
    BTFTypeMap btf_type_map;

    /// The BTF type ID generator
    std::uint32_t btf_type_id_generator{};

    /// The LLVM module where types are imported
    llvm::Module &module;

    /// Maps a type name to the BTF id
    std::unordered_map<std::string, std::uint32_t> name_to_btf_type_id;

    /// Prevents different types with the same name from becoming public
    std::unordered_set<std::string> blocked_type_name_list;

    /// Maps a BTF struct type ID to its LLVM mapping information
    std::unordered_map<std::uint32_t, StructMapping> btf_struct_mapping;

    /// BTF type ID to LLVM type
    std::unordered_map<std::uint32_t, llvm::Type *> btf_type_id_to_llvm;

    /// LLVM type to BTF type ID
    std::unordered_map<llvm::Type *, std::uint32_t> llvm_to_btf_type_id;
  };

  /// Instance data
  std::unique_ptr<Context> d;

  static Result<ElementPtr, LLVMBridgeError>
  getElementPtr(Context &context, llvm::IRBuilder<> &builder,
                llvm::Value *opaque_pointer, llvm::Type *pointer_type,
                std::uint32_t pointer_btf_type_id, const std::string &path,
                llvm::Value *temp_storage, llvm::BasicBlock *read_failed_bb);

  /// \copydoc LLVMBridge::getType
  static Result<llvm::Type *, LLVMBridgeError> getType(const Context &context,
                                                       const std::string &name);

  /// Parses a path such as obj.subtype.array[10].value
  static std::optional<PathComponentList> parsePath(const std::string &path);

  /// Helper function for LLVMBridge::locate()
  static std::optional<StructMapping>
  locateHelper(const Context &context, StructMapping output_mapping,
               std::uint32_t btf_type_id, const std::string &component);

  /// Locates the given path component in the specified type
  static std::optional<StructMapping> locate(const Context &context,
                                             std::uint32_t btf_type_id,
                                             const std::string &component);

  /// Initializes internal types
  static void initializeInternalTypes(Context &context);

  /// Preprocesses all types
  static std::optional<LLVMBridgeError> preprocessTypes(Context &context);

  /// Returns true if the given struct member is a bitfield
  static bool isBitfield(const StructBTFType::Member &member);

  /// Expands `destination` with `bitfield`
  static bool expandBitfield(StructBTFType::Member &destination,
                             const StructBTFType::Member &bitfield);

  /// Preprocesses a BTF structure
  static std::optional<LLVMBridgeError>
  preprocessStructureType(Context &context, const StructBTFType &struct_type,
                          std::uint32_t btf_id);

  /// Preprocesses a BTF union
  static std::optional<LLVMBridgeError>
  preprocessUnionType(Context &context, const UnionBTFType &union_type,
                      std::uint32_t btf_id);

  /// Returns the bit size of the given BTF type
  static std::optional<std::uint32_t> getBTFTypeSize(const Context &context,
                                                     const BTFType &type);

  /// Returns the bit size of the given BTF type id
  static std::optional<std::uint32_t> getBTFTypeSize(const Context &context,
                                                     std::uint32_t type);

  /// Generates an ArrayBTFType of the specified size
  static std::uint32_t generatePaddingBTFArrayType(Context &context,
                                                   std::uint32_t size);

  /// Generates a padding struct member of ArrayBTFType type
  static StructBTFType::Member
  generatePaddingStructMember(Context &context, std::uint32_t size,
                              std::uint32_t offset);

  /// Gets or creates a new opaque LLVM struct
  static llvm::StructType *
  getOrCreateOpaqueStruct(Context &context, llvm::Module &module,
                          std::uint32_t id,
                          const std::optional<std::string> &opt_name);

  /// Saves the given type into the context structure for later lookup
  /// operations
  static void saveType(Context &context, std::uint32_t id, llvm::Type *type,
                       const std::optional<std::string> &opt_name);

  /// No-op importer callback
  static std::optional<LLVMBridgeError> skipType(Context &context,
                                                 llvm::Module &module,
                                                 std::uint32_t id,
                                                 const BTFType &type);

  /// Importer callback for integer types
  static std::optional<LLVMBridgeError> importIntType(Context &context,
                                                      llvm::Module &module,
                                                      std::uint32_t id,
                                                      const BTFType &type);

  /// Importer callback for pointer types
  static std::optional<LLVMBridgeError> importPtrType(Context &context,
                                                      llvm::Module &module,
                                                      std::uint32_t id,
                                                      const BTFType &type);

  /// Importer callback for array types
  static std::optional<LLVMBridgeError> importArrayType(Context &context,
                                                        llvm::Module &module,
                                                        std::uint32_t id,
                                                        const BTFType &type);

  /// Importer callback for struct types
  static std::optional<LLVMBridgeError> importStructType(Context &context,
                                                         llvm::Module &module,
                                                         std::uint32_t id,
                                                         const BTFType &type);

  /// Importer callback for union types
  static std::optional<LLVMBridgeError> importUnionType(Context &context,
                                                        llvm::Module &module,
                                                        std::uint32_t id,
                                                        const BTFType &type);

  /// Importer callback for enum types
  static std::optional<LLVMBridgeError> importEnumType(Context &context,
                                                       llvm::Module &module,
                                                       std::uint32_t id,
                                                       const BTFType &type);

  /// Importer callback for forward declaration types
  static std::optional<LLVMBridgeError> importFwdType(Context &context,
                                                      llvm::Module &module,
                                                      std::uint32_t id,
                                                      const BTFType &type);

  /// Importer callback for typedef declaration types
  static std::optional<LLVMBridgeError> importTypedefType(Context &context,
                                                          llvm::Module &module,
                                                          std::uint32_t id,
                                                          const BTFType &type);

  /// Importer callback for types with a volatile modifier
  static std::optional<LLVMBridgeError> importVolatileType(Context &context,
                                                           llvm::Module &module,
                                                           std::uint32_t id,
                                                           const BTFType &type);

  /// Importer callback for types with a restrict modifier
  static std::optional<LLVMBridgeError> importRestrictType(Context &context,
                                                           llvm::Module &module,
                                                           std::uint32_t id,
                                                           const BTFType &type);

  /// Importer callback for types with a const modifier
  static std::optional<LLVMBridgeError> importConstType(Context &context,
                                                        llvm::Module &module,
                                                        std::uint32_t id,
                                                        const BTFType &type);

  /// Importer callback for function types
  static std::optional<LLVMBridgeError>
  importFuncProtoType(Context &context, llvm::Module &module, std::uint32_t id,
                      const BTFType &type);

  /// Importer callback for float types
  static std::optional<LLVMBridgeError> importFloatType(Context &context,
                                                        llvm::Module &module,
                                                        std::uint32_t id,
                                                        const BTFType &type);
};

} // namespace tob::ebpf
