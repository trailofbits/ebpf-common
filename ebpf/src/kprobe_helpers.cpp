/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "kprobe_helpers.h"

#include <cstring>
#include <fstream>
#include <sstream>
#include <string>

namespace tob::ebpf {
namespace {
const std::string kKprobeTypePath{"/sys/bus/event_source/devices/kprobe/type"};
const std::string kKprobeReturnBitPath{
    "/sys/bus/event_source/devices/kprobe/format/retprobe"};

const std::string kUprobeTypePath{"/sys/bus/event_source/devices/uprobe/type"};
const std::string kUprobeReturnBitPath{
    "/sys/bus/event_source/devices/uprobe/format/retprobe"};

StringErrorOr<std::string> readFile(const std::string &path) {
  std::ifstream input_file(path);

  std::stringstream buffer;
  buffer << input_file.rdbuf();

  if (!input_file) {
    return StringError::create("Failed to read the following file: " + path);
  }

  return buffer.str();
}

StringErrorOr<std::uint32_t> getKprobeType(const std::string &path) {
  auto buffer_exp = readFile(path);
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

StringErrorOr<bool> getKprobeReturnBit(const std::string &path) {
  auto buffer_exp = readFile(path);
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

StringErrorOr<std::uint32_t> getKprobeType() {
  return getKprobeType(kKprobeTypePath);
}

StringErrorOr<std::uint32_t> getUprobeType() {
  return getKprobeType(kUprobeTypePath);
}

StringErrorOr<bool> getKprobeReturnBit() {
  return getKprobeReturnBit(kKprobeReturnBitPath);
}

StringErrorOr<bool> getUprobeReturnBit() {
  return getKprobeReturnBit(kUprobeReturnBitPath);
}
} // namespace tob::ebpf