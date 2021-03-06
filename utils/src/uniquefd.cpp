/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include <unistd.h>

#include <tob/utils/uniquefd.h>

namespace tob::utils {
void FdDeleter::operator()(FdDeleter::Reference fd) const {
  if (fd == -1) {
    return;
  }

  close(fd);
}
} // namespace tob::utils
