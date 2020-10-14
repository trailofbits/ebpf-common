/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <cstddef>

namespace tob::ebpf {
std::size_t getPossibleProcessorCount();
} // namespace tob::ebpf