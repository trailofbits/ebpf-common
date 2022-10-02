/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "rawtracepointevent.h"

#include <tob/utils/uniquefd.h>

namespace tob::ebpf {
struct RawTracepointEvent::PrivateData final {
  std::optional<std::string> opt_name;
  utils::UniqueFd event{-1};
};

RawTracepointEvent::~RawTracepointEvent() {}

RawTracepointEvent::Type RawTracepointEvent::type() const {
  return d->opt_name.has_value() ? Type::RawTracepoint : Type::LSM;
}

std::string RawTracepointEvent::name() const {
  return d->opt_name.value_or("");
}

void RawTracepointEvent::setFileDescriptor(int fd) { d->event.reset(fd); }

int RawTracepointEvent::fd() const { return d->event.get(); }

bool RawTracepointEvent::isSyscallKprobe() const { return false; }

bool RawTracepointEvent::usesKprobeIndirectPtRegs() const { return false; }

RawTracepointEvent::RawTracepointEvent(
    const std::optional<std::string> &opt_name)
    : d(new PrivateData) {

  d->opt_name = opt_name;
}
} // namespace tob::ebpf
