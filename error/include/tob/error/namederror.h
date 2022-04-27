/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <optional>

namespace tob {

template <typename ErrorCodeWrapper> class NamedError final {
public:
  using Code = typename ErrorCodeWrapper::ErrorCode;

  static NamedError
  create(const typename ErrorCodeWrapper::ErrorCode &error_code,
         const std::optional<std::string> &opt_message = std::nullopt) {
    return NamedError(error_code, opt_message);
  }

  ~NamedError() = default;

  typename ErrorCodeWrapper::ErrorCode code() const { return error_code; }

  const std::string &name() const { return error_code_wrapper(error_code); }
  const std::optional<std::string> message() const { return opt_message; }
  const std::string &description() const { return error_description; }

  operator std::string() const { return description(); }

private:
  typename ErrorCodeWrapper::ErrorCode error_code;
  ErrorCodeWrapper error_code_wrapper;
  std::optional<std::string> opt_message;
  std::string error_description;

  NamedError(const typename ErrorCodeWrapper::ErrorCode &error_code_,
             const std::optional<std::string> &opt_message_)
      : error_code(error_code_), opt_message(opt_message_) {
    if (opt_message.has_value()) {
      error_description = opt_message.value() + " ";
    }

    error_description += "Error code: " + name();
  }
};

} // namespace tob
