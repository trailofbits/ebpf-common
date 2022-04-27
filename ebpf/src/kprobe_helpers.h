/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <tob/error/stringerror.h>

namespace tob::ebpf {
StringErrorOr<std::uint32_t> getKprobeType();
StringErrorOr<std::uint32_t> getUprobeType();

StringErrorOr<bool> getKprobeReturnBit();
StringErrorOr<bool> getUprobeReturnBit();
} // namespace tob::ebpf
