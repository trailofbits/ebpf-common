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

#include <tob/error/stringerror.h>

namespace tob::ebpf {

extern const std::size_t kPerfEventHeaderSize;

class PerfEventArray final {
public:
  using Ref = std::unique_ptr<PerfEventArray>;
  static StringErrorOr<Ref> create(std::size_t perf_event_output_page_exp);

  ~PerfEventArray();

  std::size_t memoryUsage() const;

  int fd() const;

  using Buffer = std::vector<std::uint8_t>;
  using BufferList = std::vector<Buffer>;

  bool read(BufferList &buffer_list, std::size_t &read_error_count,
            std::size_t &lost_event_count,
            const std::chrono::milliseconds &timeout =
                std::chrono::milliseconds(1000U));

  PerfEventArray(const PerfEventArray &) = delete;
  PerfEventArray &operator=(const PerfEventArray &) = delete;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  PerfEventArray(std::size_t perf_event_output_page_exp);
  BufferList readPerfMemory(std::size_t processor_index);
};

} // namespace tob::ebpf
