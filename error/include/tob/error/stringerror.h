/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <string>

#include <tob/error/erroror.h>
#include <tob/error/errorstatus.h>
#include <tob/error/stringerror.h>
#include <tob/error/successor.h>

namespace tob {

class StringError final {
public:
  static StringError create(const std::string &message) {
    return StringError(message);
  }

  StringError() : message_("Uninitialized error message") {}

  const std::string &message() const { return message_; }

protected:
  StringError(const std::string &message) : message_(message) {}

private:
  std::string message_;
};

template <typename ValueType>
using StringErrorOr = ErrorOr<ValueType, StringError>;

using SuccessOrStringError = SuccessOr<StringError>;

} // namespace tob
