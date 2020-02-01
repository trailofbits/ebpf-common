/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "kprobeperfevent.h"
#include "kprobe_helpers.h"

#include <linux/perf_event.h>
#include <linux/unistd.h>
#include <unistd.h>

#include <tob/utils/uniquefd.h>

namespace tob::ebpf {
struct KprobePerfEvent::PrivateData final {
  std::string name;
  bool ret_probe{false};
  std::uint32_t identifier{0U};
  utils::UniqueFd event;
};

KprobePerfEvent::~KprobePerfEvent() {}

KprobePerfEvent::Type KprobePerfEvent::type() const {
  return d->ret_probe ? Type::Kretprobe : Type::Kprobe;
}

const std::string &KprobePerfEvent::name() const { return d->name; }

std::uint32_t KprobePerfEvent::identifier() const { return d->identifier; }

int KprobePerfEvent::fd() const { return d->event.get(); }

KprobePerfEvent::KprobePerfEvent(const std::string &name, bool ret_probe,
                                 std::uint32_t identifier,
                                 std::int32_t process_id)
    : d(new PrivateData) {

  d->name = name;
  d->identifier = identifier;
  d->ret_probe = ret_probe;

  struct perf_event_attr attr = {};
  attr.sample_period = 1;
  attr.wakeup_events = 1;
  attr.size = sizeof(attr);

  auto string_ptr = name.c_str();
  std::memcpy(&attr.kprobe_func, &string_ptr, sizeof(string_ptr));

  auto probe_type_exp = getKprobeType();
  if (!probe_type_exp.succeeded()) {
    throw probe_type_exp.error();
  }

  attr.type = probe_type_exp.takeValue();

  if (ret_probe) {
    auto probe_return_bit_exp = getKprobeReturnBit();
    if (!probe_return_bit_exp.succeeded()) {
      throw probe_return_bit_exp.error();
    }

    auto probe_return_bit = probe_return_bit_exp.takeValue();
    attr.config |= 1 << probe_return_bit;
  }

  int cpu_index;
  if (process_id != -1) {
    cpu_index = -1;
  } else {
    cpu_index = 0;
  }

  auto fd = static_cast<int>(::syscall(__NR_perf_event_open, &attr, process_id,
                                       cpu_index, -1, PERF_FLAG_FD_CLOEXEC));

  if (fd == -1) {
    std::string event_type = ret_probe ? "exit" : "enter";
    throw StringError::create("Failed to create the " + event_type +
                              "Kprobe event. Errno: " + std::to_string(errno));
  }

  d->event.reset(fd);
}
} // namespace tob::ebpf
