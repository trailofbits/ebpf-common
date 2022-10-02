/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "tracepointevent.h"

#include <fstream>
#include <iostream>

#include <linux/perf_event.h>
#include <linux/unistd.h>
#include <unistd.h>

#include <tob/ebpf/tracepointdescriptor.h>
#include <tob/utils/uniquefd.h>

namespace tob::ebpf {
namespace {
const std::string kTracepointRootPath = "/sys/kernel/debug/tracing/events/";
} // namespace

struct TracepointEvent::PrivateData final {
  std::string category;
  std::string name;
  utils::UniqueFd event;
};

TracepointEvent::~TracepointEvent() {}

TracepointEvent::Type TracepointEvent::type() const { return Type::Tracepoint; }

int TracepointEvent::fd() const { return d->event.get(); }

std::string TracepointEvent::name() const {
  return d->category + ":" + d->name;
}

bool TracepointEvent::isSyscallKprobe() const { return false; }

bool TracepointEvent::usesKprobeIndirectPtRegs() const { return false; }

TracepointEvent::TracepointEvent(const std::string &category,
                                 const std::string &name,
                                 std::int32_t process_id)
    : d(new PrivateData) {

  // Open the tracepoint
  d->category = category;
  d->name = name;

  auto tracepoint_desc_exp =
      ebpf::TracepointDescriptor::create(category, d->name);

  if (!tracepoint_desc_exp.succeeded()) {
    throw tracepoint_desc_exp.error();
  }

  auto tracepoint_desc = tracepoint_desc_exp.takeValue();
  auto tracepoint_id = tracepoint_desc->eventIdentifier();

  int cpu_index;
  if (process_id != -1) {
    cpu_index = -1;
  } else {
    cpu_index = 0;
  }

  struct perf_event_attr perf_attr = {};
  perf_attr.type = PERF_TYPE_TRACEPOINT;
  perf_attr.size = sizeof(struct perf_event_attr);
  perf_attr.config = tracepoint_id;
  perf_attr.sample_period = 1;
  perf_attr.sample_type = PERF_SAMPLE_RAW;
  perf_attr.wakeup_events = 1;
  perf_attr.disabled = 1;

  auto fd =
      static_cast<int>(::syscall(__NR_perf_event_open, &perf_attr, process_id,
                                 cpu_index, -1, PERF_FLAG_FD_CLOEXEC));

  if (fd == -1) {
    throw StringError::create("Failed to create the tracepoint event");
  }

  d->event.reset(fd);
}
} // namespace tob::ebpf
