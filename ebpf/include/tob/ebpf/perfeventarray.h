/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <vector>

#include <tob/error/error.h>

namespace tob::ebpf {
class PerfEventArray final {
public:
  using Ref = std::unique_ptr<PerfEventArray>;
  static StringErrorOr<Ref> create(std::size_t perf_event_output_page_exp);

  ~PerfEventArray();

  std::size_t memoryUsage() const;

  int fd() const;

  bool read(std::vector<std::uint8_t> &buffer, std::size_t &read_error_count,
            std::size_t &lost_event_count,
            const std::chrono::milliseconds &timeout =
                std::chrono::milliseconds(1000U));

  PerfEventArray(const PerfEventArray &) = delete;
  PerfEventArray &operator=(const PerfEventArray &) = delete;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  using PerfBuffer = std::vector<std::uint8_t>;
  using PerfBufferList = std::vector<PerfBuffer>;

  PerfEventArray(std::size_t perf_event_output_page_exp);

  PerfBufferList readPerfMemory(std::size_t processor_index);
};
} // namespace tob::ebpf
