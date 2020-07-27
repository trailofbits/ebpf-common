/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include <unistd.h>

#include <tob/utils/architecture.h>

namespace tob::utils {
StringErrorOr<Architecture> getProcessorArchitecture() {
#if defined(__i386__)
  return Architecture::x86;

#elif defined(__arm__)
  return Architecture::AArch32;

#elif defined(__x86_64__)
  return Architecture::x64;

#elif defined(__aarch64__)
  return Architecture::AArch64;

#else
  return StringError::create("Unsupported architecture");
#endif
}

StringErrorOr<std::size_t> getProcessorBitness() {
  auto architecture_exp = getProcessorArchitecture();
  if (!architecture_exp.succeeded()) {
    return architecture_exp.error();
  }

  auto architecture = architecture_exp.takeValue();

  switch (architecture) {
  case Architecture::x86:
  case Architecture::AArch32:
    return 32U;

  case Architecture::x64:
  case Architecture::AArch64:
    return 64U;

  default:
    throw std::logic_error("Invalid or unsupported architecture");
  }
}
} // namespace tob::utils
