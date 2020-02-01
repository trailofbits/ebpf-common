/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "uprobeperfevent.h"
#include "kprobe_helpers.h"

#include <linux/perf_event.h>
#include <linux/unistd.h>
#include <unistd.h>

#include <tob/utils/uniquefd.h>

namespace tob::ebpf {
namespace {
StringErrorOr<std::uint64_t> getSymbolFileOffset(const std::string &path,
                                                 const std::string &name) {
  static_cast<void>(path);
  static_cast<void>(name);

  return 0x17800ULL;
}
} // namespace
struct UprobePerfEvent::PrivateData final {
  std::string name;
  std::string path;
  bool ret_probe{false};
  std::uint32_t identifier{0U};
  utils::UniqueFd event;
  std::uint64_t offset{0U};
};

UprobePerfEvent::~UprobePerfEvent() {}

UprobePerfEvent::Type UprobePerfEvent::type() const {
  return d->ret_probe ? Type::Uretprobe : Type::Uprobe;
}

const std::string &UprobePerfEvent::name() const { return d->name; }

std::uint32_t UprobePerfEvent::identifier() const { return d->identifier; }

int UprobePerfEvent::fd() const { return d->event.get(); }

UprobePerfEvent::UprobePerfEvent(const std::string &name,
                                 const std::string &path, bool ret_probe,
                                 std::uint32_t identifier,
                                 std::int32_t process_id)
    : d(new PrivateData) {

  d->name = name;
  d->path = path;
  d->identifier = identifier;
  d->ret_probe = ret_probe;

  auto symbol_offset_exp = getSymbolFileOffset(path, name);
  if (!symbol_offset_exp.succeeded()) {
    throw symbol_offset_exp.error();
  }

  d->offset = symbol_offset_exp.takeValue();

  struct perf_event_attr attr = {};
  attr.sample_period = 1;
  attr.wakeup_events = 1;
  attr.size = sizeof(attr);

  auto path_ptr = path.c_str();
  std::memcpy(&attr.uprobe_path, &path_ptr, sizeof(path_ptr));

  attr.probe_offset = static_cast<__u64>(d->offset);

  auto probe_type_exp = getUprobeType();
  if (!probe_type_exp.succeeded()) {
    throw probe_type_exp.error();
  }

  attr.type = probe_type_exp.takeValue();

  if (ret_probe) {
    auto probe_return_bit_exp = getUprobeReturnBit();
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
                              " Uprobe event. Errno: " + std::to_string(errno));
  }

  d->event.reset(fd);
}
} // namespace tob::ebpf
