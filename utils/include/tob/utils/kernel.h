/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <tob/error/stringerror.h>

namespace tob::utils {

struct KernelVersion final {
  std::uint32_t major{};
  std::uint32_t minor{};
};

StringErrorOr<KernelVersion> getKernelVersion();

} // namespace tob::utils
