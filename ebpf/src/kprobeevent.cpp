/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "kprobeevent.h"
#include "kprobe_helpers.h"

#include <cstdint>

#include <linux/perf_event.h>
#include <linux/unistd.h>
#include <unistd.h>

#include <tob/utils/kernel.h>
#include <tob/utils/uniquefd.h>

namespace tob::ebpf {
struct KprobeEvent::PrivateData final {
  std::string name;
  bool ret_probe{false};
  bool is_syscall{false};
  utils::UniqueFd event;
};

KprobeEvent::~KprobeEvent() {}

KprobeEvent::Type KprobeEvent::type() const {
  return d->ret_probe ? Type::Kretprobe : Type::Kprobe;
}

int KprobeEvent::fd() const { return d->event.get(); }

std::string KprobeEvent::name() const { return d->name; }

bool KprobeEvent::isSyscallKprobe() const { return d->is_syscall; }

bool KprobeEvent::usesKprobeIndirectPtRegs() const {
  auto kernel_version_exp = utils::getKernelVersion();
  if (!kernel_version_exp.succeeded()) {
    return false;
  }

  auto kernel_version = kernel_version_exp.takeValue();

  bool indirect_pt_regs{false};
  if (kernel_version.major <= 3) {
    indirect_pt_regs = false;

  } else if (kernel_version.major == 4) {
    indirect_pt_regs = kernel_version.minor < 16;

  } else {
    indirect_pt_regs = true;
  }

  return indirect_pt_regs;
}

KprobeEvent::KprobeEvent(const std::string &name, bool ret_probe,
                         bool is_syscall, std::int32_t process_id)
    : d(new PrivateData) {

  d->name = name;
  d->ret_probe = ret_probe;
  d->is_syscall = is_syscall;

  struct perf_event_attr attr = {};
  attr.sample_period = 1;
  attr.wakeup_events = 1;
  attr.size = sizeof(attr);

  auto string_ptr = name.c_str();
  std::memcpy(&attr.config1, &string_ptr, sizeof(string_ptr));

  auto probe_type_exp = getKprobeType();
  if (!probe_type_exp.succeeded()) {
    throw probe_type_exp.error();
  }

  attr.type = probe_type_exp.takeValue();

  if (d->ret_probe) {
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
    std::string event_type = d->ret_probe ? "exit" : "enter";
    throw StringError::create("Failed to create the " + event_type +
                              "Kprobe event. Errno: " + std::to_string(errno));
  }

  d->event.reset(fd);
}
} // namespace tob::ebpf
