/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "clanginitializer.h"

namespace tob::ebpf {

ClangInitializer::ClangInitializer() {
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllAsmPrinters();
  llvm::InitializeAllTargets();
}

const ClangInitializer kClangInitializer;

} // namespace tob::ebpf
