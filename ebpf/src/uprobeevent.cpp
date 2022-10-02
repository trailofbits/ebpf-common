/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "uprobeevent.h"
#include "kprobe_helpers.h"

#include <linux/perf_event.h>
#include <linux/unistd.h>
#include <unistd.h>

#include <tob/utils/ielfimage.h>
#include <tob/utils/uniquefd.h>

namespace tob::ebpf {
namespace {
StringErrorOr<std::uint64_t> getSymbolFileOffset(const std::string &path,
                                                 const std::string &name) {

  auto elf_image_exp = utils::IELFImage::create(path);
  if (!elf_image_exp.succeeded()) {
    return elf_image_exp.error();
  }

  auto elf_image = elf_image_exp.takeValue();

  auto function_offset_exp = elf_image->getExportedFunctionAddress(name);
  if (!function_offset_exp.succeeded()) {
    return function_offset_exp.error();
  }

  return function_offset_exp.takeValue();
}
} // namespace

struct UprobeEvent::PrivateData final {
  std::string name;
  bool ret_probe{false};
  utils::UniqueFd event;
};

UprobeEvent::~UprobeEvent() {}

UprobeEvent::Type UprobeEvent::type() const {
  return d->ret_probe ? Type::Uretprobe : Type::Uprobe;
}

int UprobeEvent::fd() const { return d->event.get(); }

std::string UprobeEvent::name() const { return d->name; }

bool UprobeEvent::isSyscallKprobe() const { return false; }

bool UprobeEvent::usesKprobeIndirectPtRegs() const { return false; }

UprobeEvent::UprobeEvent(const std::string &name, const std::string &path,
                         bool ret_probe, std::int32_t process_id)
    : d(new PrivateData) {

  d->name = name;
  d->ret_probe = ret_probe;

  auto symbol_offset_exp = getSymbolFileOffset(path, name);
  if (!symbol_offset_exp.succeeded()) {
    throw symbol_offset_exp.error();
  }

  auto offset = symbol_offset_exp.takeValue();

  struct perf_event_attr attr = {};
  attr.sample_period = 1;
  attr.wakeup_events = 1;
  attr.size = sizeof(attr);

  auto path_ptr = path.c_str();
  std::memcpy(&attr.config1, &path_ptr, sizeof(path_ptr));

  attr.config2 = static_cast<__u64>(offset);

  auto probe_type_exp = getUprobeType();
  if (!probe_type_exp.succeeded()) {
    throw probe_type_exp.error();
  }

  attr.type = probe_type_exp.takeValue();

  if (d->ret_probe) {
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
    std::string event_type = d->ret_probe ? "exit" : "enter";
    throw StringError::create("Failed to create the " + event_type +
                              " Uprobe event. Errno: " + std::to_string(errno));
  }

  d->event.reset(fd);
}
} // namespace tob::ebpf
