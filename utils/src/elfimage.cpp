/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "elfimage.h"

#include <algorithm>
#include <array>
#include <cstring>

namespace tob::utils {
namespace {
template <typename Type>
void readBufferValue(Type &destination, char *&buffer_ptr) {
  std::memcpy(&destination, buffer_ptr, sizeof(Type));
  buffer_ptr += sizeof(Type);
}
} // namespace

struct ELFImage::PrivateData final {
  SymbolList symbol_list;
};

ELFImage::~ELFImage() {}

ELFImage::ELFImage(const std::string &path) : d(new PrivateData) {
  std::fstream elf_image{path, std::ios::in};
  if (!elf_image) {
    throw StringError::create("Failed to open the following ELF image: " +
                              path);
  }

  auto header_exp = getImageHeader(elf_image);
  if (!header_exp.succeeded()) {
    throw header_exp.error();
  }

  auto header = header_exp.takeValue();

  auto section_header_list_exp = getSectionHeaderList(elf_image, header);
  if (!section_header_list_exp.succeeded()) {
    throw section_header_list_exp.error();
  }

  auto section_header_list = section_header_list_exp.takeValue();

  auto section_string_table_exp =
      getSectionStringTable(elf_image, header, section_header_list);

  if (!section_string_table_exp.succeeded()) {
    throw section_string_table_exp.error();
  }

  auto section_string_table = section_string_table_exp.takeValue();

  auto dynsym_section_exp = getSection(elf_image, section_header_list,
                                       section_string_table, ".dynsym");

  if (!dynsym_section_exp.succeeded()) {
    throw dynsym_section_exp.error();
  }

  auto dynsym_section = dynsym_section_exp.takeValue();

  auto dynstr_section_exp = getSection(elf_image, section_header_list,
                                       section_string_table, ".dynstr");

  if (!dynstr_section_exp.succeeded()) {
    throw dynstr_section_exp.error();
  }

  auto dynstr_section = dynstr_section_exp.takeValue();

  auto symbol_list_exp = parseSymbolSection(dynsym_section, dynstr_section);
  if (!symbol_list_exp.succeeded()) {
    throw symbol_list_exp.error();
  }

  d->symbol_list = symbol_list_exp.takeValue();
}

StringErrorOr<std::uintptr_t>
ELFImage::getExportedFunctionAddress(const std::string &name) {
  // clang-format off
  auto symbol_it = std::find_if(
    d->symbol_list.begin(),
    d->symbol_list.end(),

    [name](const Symbol &symbol) -> bool {
      return (symbol.name == name);
    }
  );
  // clang-format on

  if (symbol_it == d->symbol_list.end()) {
    return StringError::create("The following symbol was not found: " + name);
  }

  const auto &symbol = *symbol_it;
  return static_cast<std::uint64_t>(symbol.header.st_value);
}

StringErrorOr<Elf64_Ehdr> ELFImage::getImageHeader(std::fstream &elf_image) {
  elf_image.seekg(0);

  std::array<char, sizeof(Elf64_Ehdr)> buffer;
  elf_image.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
  if (!elf_image) {
    return StringError::create("Failed to read the ELF header");
  }

  auto buffer_ptr = buffer.data();

  Elf64_Ehdr header{};
  readBufferValue<decltype(Elf64_Ehdr::e_ident)>(header.e_ident, buffer_ptr);
  readBufferValue<Elf64_Half>(header.e_type, buffer_ptr);
  readBufferValue<Elf64_Half>(header.e_machine, buffer_ptr);
  readBufferValue<Elf64_Word>(header.e_version, buffer_ptr);
  readBufferValue<Elf64_Addr>(header.e_entry, buffer_ptr);
  readBufferValue<Elf64_Off>(header.e_phoff, buffer_ptr);
  readBufferValue<Elf64_Off>(header.e_shoff, buffer_ptr);
  readBufferValue<Elf64_Word>(header.e_flags, buffer_ptr);
  readBufferValue<Elf64_Half>(header.e_ehsize, buffer_ptr);
  readBufferValue<Elf64_Half>(header.e_phentsize, buffer_ptr);
  readBufferValue<Elf64_Half>(header.e_phnum, buffer_ptr);
  readBufferValue<Elf64_Half>(header.e_shentsize, buffer_ptr);
  readBufferValue<Elf64_Half>(header.e_shnum, buffer_ptr);
  readBufferValue<Elf64_Half>(header.e_shstrndx, buffer_ptr);

  return header;
}

StringErrorOr<std::vector<Elf64_Shdr>>
ELFImage::getSectionHeaderList(std::fstream &elf_image,
                               const Elf64_Ehdr &header) {

  auto section_header_count = static_cast<std::size_t>(header.e_shnum);
  auto section_header_table_size = section_header_count * sizeof(Elf64_Shdr);

  auto section_header_table_off = static_cast<std::streamoff>(header.e_shoff);
  elf_image.seekg(section_header_table_off);

  std::vector<char> buffer(section_header_table_size, 0U);
  elf_image.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
  if (!elf_image) {
    return StringError::create("Failed to read the section header table");
  }

  std::vector<Elf64_Shdr> section_header_list;
  section_header_list.resize(section_header_count);

  auto buffer_ptr = buffer.data();
  for (auto &section : section_header_list) {
    readBufferValue<Elf64_Word>(section.sh_name, buffer_ptr);
    readBufferValue<Elf64_Word>(section.sh_type, buffer_ptr);
    readBufferValue<Elf64_Xword>(section.sh_flags, buffer_ptr);
    readBufferValue<Elf64_Addr>(section.sh_addr, buffer_ptr);
    readBufferValue<Elf64_Off>(section.sh_offset, buffer_ptr);
    readBufferValue<Elf64_Xword>(section.sh_size, buffer_ptr);
    readBufferValue<Elf64_Word>(section.sh_link, buffer_ptr);
    readBufferValue<Elf64_Word>(section.sh_info, buffer_ptr);
    readBufferValue<Elf64_Xword>(section.sh_addralign, buffer_ptr);
    readBufferValue<Elf64_Xword>(section.sh_entsize, buffer_ptr);
  }

  return section_header_list;
}

StringErrorOr<std::vector<char>> ELFImage::getSectionStringTable(
    std::fstream &elf_image, const Elf64_Ehdr &header,
    const std::vector<Elf64_Shdr> &section_header_list) {

  auto string_section_index = static_cast<std::size_t>(header.e_shstrndx);

  if (string_section_index >= section_header_list.size()) {
    return StringError::create("Invalid section header index");
  }

  const auto &string_section_header =
      section_header_list.at(string_section_index);

  auto section_offset =
      static_cast<std::streamoff>(string_section_header.sh_offset);

  auto section_size = static_cast<std::size_t>(string_section_header.sh_size);

  elf_image.seekg(section_offset);
  if (!elf_image) {
    return StringError::create("Failed to seek to the string section");
  }

  std::vector<char> buffer;
  buffer.resize(section_size);

  elf_image.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
  if (!elf_image) {
    return StringError::create("Failed to read the string section");
  }

  return buffer;
}

StringErrorOr<std::string>
ELFImage::getStringTableEntry(const std::vector<char> &string_table,
                              std::size_t index) {
  if (index == 0U) {
    return std::string();
  }

  if (index >= string_table.size()) {
    return StringError::create("Invalid string table index");
  }

  const char *base_string_ptr = string_table.data() + index;
  auto remaining_bytes = string_table.size() - index;

  auto length = strnlen(base_string_ptr, remaining_bytes);
  if (length == remaining_bytes && string_table[length - 1] != 0) {
    return StringError::create(
        "Failed to locate the string in the string table");
  }

  return std::string(base_string_ptr, length);
}

StringErrorOr<Elf64_Shdr>
ELFImage::getSectionHeader(const std::vector<Elf64_Shdr> &section_header_list,
                           const std::vector<char> &string_table,
                           const std::string &section_name) {

  if (section_name.empty()) {
    return StringError::create("Not possible to locate an unnamed section");
  }

  for (const auto &section_header : section_header_list) {
    if (section_header.sh_name == 0) {
      continue;
    }

    auto section_name_exp =
        getStringTableEntry(string_table, section_header.sh_name);

    if (!section_name_exp.succeeded()) {
      return section_name_exp.error();
    }

    auto current_section_name = section_name_exp.takeValue();
    if (current_section_name == section_name) {
      return section_header;
    }
  }

  return StringError::create("Failed to locate the specified section");
}

StringErrorOr<std::vector<char>> ELFImage::getSection(
    std::fstream &elf_image, const std::vector<Elf64_Shdr> &section_header_list,
    const std::vector<char> &string_table, const std::string &section_name) {

  auto section_header_exp =
      getSectionHeader(section_header_list, string_table, section_name);

  if (!section_header_exp.succeeded()) {
    return section_header_exp.error();
  }

  auto section_header = section_header_exp.takeValue();
  auto section_size = static_cast<std::streamsize>(section_header.sh_size);
  auto section_offset = static_cast<std::streamoff>(section_header.sh_offset);

  std::vector<char> buffer;
  buffer.resize(static_cast<std::size_t>(section_size));

  elf_image.seekg(section_offset);
  if (!elf_image) {
    return StringError::create("Failed to read the section data");
  }

  elf_image.read(buffer.data(), section_size);
  if (!elf_image) {
    return StringError::create("Failed to read the section data");
  }

  return buffer;
}

StringErrorOr<ELFImage::SymbolList>
ELFImage::parseSymbolSection(const std::vector<char> &symbol_section,
                             const std::vector<char> &string_table) {

  auto symbol_count = symbol_section.size() / sizeof(Elf64_Sym);
  if ((symbol_section.size() % sizeof(Elf64_Sym)) != 0) {
    return StringError::create("Invalid .dynsym section size");
  }

  SymbolList symbol_list;

  for (auto i = 0U; i < symbol_count; ++i) {
    auto base_offset = symbol_section.data() + (i * sizeof(Elf64_Sym));

    Symbol symbol = {};
    std::memcpy(&symbol.header, base_offset, sizeof(symbol.header));

    auto symbol_name_exp =
        getStringTableEntry(string_table, symbol.header.st_name);

    if (!symbol_name_exp.succeeded()) {
      continue;
    }

    symbol.name = symbol_name_exp.takeValue();
    symbol_list.push_back(std::move(symbol));
  }

  return symbol_list;
}

StringErrorOr<IELFImage::Ref> IELFImage::create(const std::string &path) {
  try {
    return Ref(new ELFImage(path));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}
} // namespace tob::utils
