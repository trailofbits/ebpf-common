/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace tob::ebpf {

std::size_t getPossibleProcessorCount();
std::vector<std::size_t> parseCpuList(const std::string &cpu_list_str);
std::vector<std::size_t> getOnlineProcessorList();

} // namespace tob::ebpf