/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "kprobeperfevent.h"

#include <fstream>
#include <sstream>

#include <linux/perf_event.h>
#include <linux/unistd.h>
#include <unistd.h>

#include <tob/utils/uniquefd.h>

namespace tob::ebpf {
namespace {
const std::string kKprobeTypePath{
    "/sys/bus/event_source/devices/kprobe/subsystem/devices/kprobe/type"};

const std::string kKprobeReturnBitPath{"/sys/devices/kprobe/format/retprobe"};

StringErrorOr<std::string> readFile(const std::string &path) {
  std::ifstream input_file(path);

  std::stringstream buffer;
  buffer << input_file.rdbuf();

  if (!input_file) {
    return StringError::create("Failed to read the following file: " + path);
  }

  return buffer.str();
}

StringErrorOr<std::uint32_t> getKProbeType() {
  auto buffer_exp = readFile(kKprobeTypePath);
  if (!buffer_exp.succeeded()) {
    return buffer_exp.error();
  }

  auto buffer = buffer_exp.takeValue();

  char *integer_terminator{nullptr};
  auto integer_value = std::strtol(buffer.data(), &integer_terminator, 10);

  if (!(integer_terminator != nullptr && std::isspace(*integer_terminator))) {
    return StringError::create("Failed to parse the integer value");
  }

  return static_cast<std::uint32_t>(integer_value);
}

StringErrorOr<bool> getKprobeReturnBit() {
  auto buffer_exp = readFile(kKprobeReturnBitPath);
  if (!buffer_exp.succeeded()) {
    return buffer_exp.error();
  }

  auto buffer = buffer_exp.takeValue();

  auto value_ptr = buffer.data() + std::strlen("config:");
  if (value_ptr >= buffer.data() + buffer.size()) {
    return StringError::create("Invalid buffer contents");
  }

  char *integer_terminator{nullptr};
  auto integer_value = std::strtol(value_ptr, &integer_terminator, 10);

  if (!(integer_terminator != nullptr && std::isspace(*integer_terminator))) {
    return StringError::create("Failed to parse the integer value");
  }

  if (integer_value == 0) {
    return false;

  } else if (integer_value == 1) {
    return true;

  } else {
    return StringError::create("Unexpected integer value");
  }
}
} // namespace

struct KprobePerfEvent::PrivateData final {
  std::string name;
  bool ret_probe{false};
  std::uint64_t identifier{0U};
  utils::UniqueFd event;
};

KprobePerfEvent::~KprobePerfEvent() {}

KprobePerfEvent::Type KprobePerfEvent::type() const {
  return d->ret_probe ? Type::Kretprobe : Type::Kprobe;
}

const std::string &KprobePerfEvent::name() const { return d->name; }

std::uint64_t KprobePerfEvent::identifier() const { return d->identifier; }

int KprobePerfEvent::fd() const { return d->event.get(); }

KprobePerfEvent::KprobePerfEvent(const std::string &name, bool ret_probe,
                                 std::uint64_t identifier,
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
  std::memcpy(&attr.config1, &string_ptr, sizeof(string_ptr));

  auto probe_type_exp = getKProbeType();
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
    throw StringError::create("Failed to create the Kprobe event. Errno: " +
                              std::to_string(errno));
  }

  d->event.reset(fd);
}
} // namespace tob::ebpf
