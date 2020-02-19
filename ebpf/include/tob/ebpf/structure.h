/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <string>
#include <vector>

namespace tob::ebpf {
struct StructureField final {
  std::string type;
  std::string name;
  std::size_t offset{0U};
  std::size_t size{0U};
  bool is_signed{false};
};

using Structure = std::vector<StructureField>;
} // namespace tob::ebpf
