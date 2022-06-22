/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "clangcompiler.h"

#include <tob/ebpf/iclangcompiler.h>

namespace tob::ebpf {

StringErrorOr<IClangCompiler::Ptr>
IClangCompiler::create(const std::filesystem::path &btf_file_path) {
  try {
    return Ptr(new ClangCompiler(btf_file_path));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}

} // namespace tob::ebpf
