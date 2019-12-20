/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <tob/error/errorcode.h>
#include <tob/error/erroror.h>
#include <tob/error/stringerror.h>
#include <tob/error/successor.h>

namespace tob {
template <typename ValueType>
using StringErrorOr = ErrorOr<ValueType, StringError>;

using SuccessOrStringError = SuccessOr<StringError>;
} // namespace tob
