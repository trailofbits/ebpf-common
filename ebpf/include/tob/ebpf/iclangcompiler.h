/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <filesystem>
#include <memory>

#include <tob/ebpf/types.h>
#include <tob/error/stringerror.h>

namespace tob::ebpf {

class IClangCompiler {
public:
  using Ptr = std::unique_ptr<IClangCompiler>;
  static StringErrorOr<Ptr> create(const std::filesystem::path &btf_file_path);

  struct Definition final {
    std::string name;
    std::string value;
  };

  using DefinitionList = std::vector<Definition>;

  virtual StringErrorOr<BPFProgramMap>
  build(const std::string &source_code,
        const DefinitionList &definition_list = {}) = 0;

  IClangCompiler() = default;
  virtual ~IClangCompiler() = default;

  IClangCompiler(const IClangCompiler &) = delete;
  IClangCompiler &operator=(const IClangCompiler &) = delete;
};

} // namespace tob::ebpf
