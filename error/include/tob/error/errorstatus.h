/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

namespace tob {
template <typename Result, typename Result::ErrorCode DefaultErrorValue>
class ErrorStatus final {
public:
  using Value = typename Result::ErrorCode;

  ErrorStatus() = default;
  ErrorStatus(typename Result::ErrorCode value) : error_value(value) {}

  typename Result::ErrorCode value() const { return error_value; }

  bool succeeded() const { return Result()(error_value); }

private:
  typename Result::ErrorCode error_value{DefaultErrorValue};
};
} // namespace tob
