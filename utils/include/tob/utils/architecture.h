/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <tob/error/stringerror.h>

namespace tob::utils {
enum class Architecture { x86, x64, AArch32, AArch64 };

StringErrorOr<Architecture> getProcessorArchitecture();
StringErrorOr<std::size_t> getProcessorBitness();
} // namespace tob::utils
