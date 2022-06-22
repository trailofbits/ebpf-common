/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <llvm/Support/TargetSelect.h>

namespace tob::ebpf {

class ClangInitializer final {
public:
  ClangInitializer();
  ~ClangInitializer() = default;

  ClangInitializer(const ClangInitializer &) = delete;
  ClangInitializer &operator=(const ClangInitializer &) = delete;
};

extern const ClangInitializer kClangInitializer;

} // namespace tob::ebpf
