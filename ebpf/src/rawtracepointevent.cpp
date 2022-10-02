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
  std::string name;
  utils::UniqueFd event{-1};
};

RawTracepointEvent::~RawTracepointEvent() {}

RawTracepointEvent::Type RawTracepointEvent::type() const {
  return Type::RawTracepoint;
}

std::string RawTracepointEvent::name() const { return d->name; }

void RawTracepointEvent::setFileDescriptor(int fd) { d->event.reset(fd); }

int RawTracepointEvent::fd() const { return d->event.get(); }

bool RawTracepointEvent::isSyscallKprobe() const { return false; }

bool RawTracepointEvent::usesKprobeIndirectPtRegs() const { return false; }

RawTracepointEvent::RawTracepointEvent(const std::string &name)
    : d(new PrivateData) {
  d->name = name;
}
} // namespace tob::ebpf
