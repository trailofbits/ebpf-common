/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include <sys/utsname.h>

#include <tob/utils/kernel.h>

namespace tob::utils {

StringErrorOr<KernelVersion> getKernelVersion() {
  KernelVersion kernel_version;

  struct utsname system_info {};
  if (uname(&system_info) != 0) {
    return StringError::create("Failed to acquire the system information");
  }

  std::sscanf(system_info.release, "%d.%d", &kernel_version.major,
              &kernel_version.minor);

  return kernel_version;
}

} // namespace tob::utils
