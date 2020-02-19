/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <tob/utils/ielfimage.h>

#include <fstream>
#include <vector>

#include <elf.h>

namespace tob::utils {
class ELFImage final : public IELFImage {
public:
  virtual ~ELFImage() override;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  ELFImage(const std::string &path);

  virtual StringErrorOr<std::uintptr_t>
  getExportedFunctionAddress(const std::string &name) override;

public:
  static StringErrorOr<Elf64_Ehdr> getImageHeader(std::fstream &elf_image);

  static StringErrorOr<std::vector<Elf64_Shdr>>
  getSectionHeaderList(std::fstream &elf_image, const Elf64_Ehdr &header);

  static StringErrorOr<std::vector<char>>
  getSectionStringTable(std::fstream &elf_image, const Elf64_Ehdr &header,
                        const std::vector<Elf64_Shdr> &section_header_list);

  static StringErrorOr<std::string>
  getStringTableEntry(const std::vector<char> &string_table, std::size_t index);

  static StringErrorOr<Elf64_Shdr>
  getSectionHeader(const std::vector<Elf64_Shdr> &section_header_list,
                   const std::vector<char> &string_table,
                   const std::string &section_name);

  static StringErrorOr<std::vector<char>>
  getSection(std::fstream &elf_image,
             const std::vector<Elf64_Shdr> &section_header_list,
             const std::vector<char> &string_table,
             const std::string &section_name);

  struct Symbol final {
    std::string name;
    Elf64_Sym header{};
  };

  using SymbolList = std::vector<Symbol>;

  static StringErrorOr<SymbolList>
  parseSymbolSection(const std::vector<char> &symbol_section,
                     const std::vector<char> &string_table);

  friend class IELFImage;
};
} // namespace tob::utils
