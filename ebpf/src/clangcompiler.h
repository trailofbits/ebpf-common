/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <memory>

#include <tob/ebpf/iclangcompiler.h>

#include <btfparse/ibtf.h>

#include <llvm/IR/Module.h>

namespace tob::ebpf {

class ClangCompiler final : public IClangCompiler {
public:
  virtual StringErrorOr<BPFProgramMap>
  build(const std::string &source_code,
        const DefinitionList &definition_list) override;

  virtual ~ClangCompiler() override;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  ClangCompiler(const std::filesystem::path &btf_file_path);

public:
  static llvm::MemoryBuffer *
  getStringAsMemoryBuffer(const std::string &source_code);

  static std::string generateDefinitionInclude(
      const IClangCompiler::DefinitionList &definition_list);

  static StringErrorOr<std::unique_ptr<llvm::Module>>
  createModule(const std::string &source_code,
               const DefinitionList &definition_list,
               const std::string &btf_include_header);

  static StringErrorOr<BPFProgramMap>
  createProgramMap(std::unique_ptr<llvm::Module> module);

  friend class IClangCompiler;
};

} // namespace tob::ebpf
