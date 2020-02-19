/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "tracepointperfevent.h"

#include <fstream>
#include <iostream>

#include <linux/perf_event.h>
#include <linux/unistd.h>
#include <unistd.h>

#include <tob/utils/uniquefd.h>

namespace tob::ebpf {
namespace {
const std::string kTracepointRootPath = "/sys/kernel/debug/tracing/events/";

bool configureTracepointEvent(const std::string &name, bool enable) {
  std::string switch_path = kTracepointRootPath + name + "/enable";

  std::fstream f(switch_path, std::ios::out | std::ios::binary);
  if (!f) {
    return false;
  }

  f << (enable ? '1' : '0');
  if (!f) {
    return false;
  }

  return true;
}
} // namespace

struct TracepointPerfEvent::PrivateData final {
  std::string name;
  std::uint32_t identifier{0U};
  utils::UniqueFd event;
};

TracepointPerfEvent::~TracepointPerfEvent() {
  if (!configureTracepointEvent(d->name, false)) {
    std::cerr << "Failed to deactivate the following tracepoint: " << d->name
              << "\n";
  }
}

TracepointPerfEvent::Type TracepointPerfEvent::type() const {
  return Type::Tracepoint;
}

const std::string &TracepointPerfEvent::name() const { return d->name; }

std::uint32_t TracepointPerfEvent::identifier() const { return d->identifier; }

int TracepointPerfEvent::fd() const { return d->event.get(); }

TracepointPerfEvent::TracepointPerfEvent(const std::string &name,
                                         std::uint32_t identifier,
                                         std::int32_t process_id)
    : d(new PrivateData) {
  d->name = name;
  d->identifier = identifier;

  int cpu_index;
  if (process_id != -1) {
    cpu_index = -1;
  } else {
    cpu_index = 0;
  }

  struct perf_event_attr perf_attr = {};
  perf_attr.type = PERF_TYPE_TRACEPOINT;
  perf_attr.size = sizeof(struct perf_event_attr);
  perf_attr.config = d->identifier;
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

  if (!configureTracepointEvent(name, true)) {
    throw StringError::create("Failed to activate the following tracepoint: " +
                              name);
  }
}
} // namespace tob::ebpf
