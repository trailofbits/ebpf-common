/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <memory>

#include <tob/error/stringerror.h>

namespace tob::utils {
class IELFImage {
public:
  using Ref = std::unique_ptr<IELFImage>;

  IELFImage() = default;
  virtual ~IELFImage() = default;

  static StringErrorOr<Ref> create(const std::string &path);

  virtual StringErrorOr<std::uintptr_t>
  getExportedFunctionAddress(const std::string &name) = 0;
};
} // namespace tob::utils
