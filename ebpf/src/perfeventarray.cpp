/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include <cmath>
#include <cstddef>
#include <vector>

#include <linux/perf_event.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#include <tob/ebpf/ebpf_utils.h>
#include <tob/ebpf/perfeventarray.h>
#include <tob/ebpf/typedbpfmap.h>

namespace tob::ebpf {

const std::size_t kPerfEventHeaderSize{sizeof(struct perf_event_header)};

namespace {

using PerfEventArrayMap =
    TypedBPFMap<BPF_MAP_TYPE_PERF_EVENT_ARRAY, std::uint32_t, int>;

static const auto kPerfDataTailOffset =
    offsetof(struct perf_event_mmap_page, data_tail);

static const auto kPerfDataSizeOffset =
    offsetof(struct perf_event_mmap_page, data_size);

static const auto kPerfDataOffsetOffset =
    offsetof(struct perf_event_mmap_page, data_offset);

static const auto kPerfDataHeadOffset =
    offsetof(struct perf_event_mmap_page, data_head);

} // namespace

struct PerfEventArray::PrivateData final {
  PerfEventArrayMap::Ref perf_event_array_map;

  std::size_t single_perf_event_output_size{};
  std::size_t processor_count{};

  std::unordered_map<std::size_t, PerfEventOutput> perf_event_output_list;
  std::vector<struct pollfd> perf_event_output_pollfd;
};

StringErrorOr<PerfEventArray::Ref>
PerfEventArray::create(std::size_t perf_event_output_page_exp) {
  try {
    return Ref(new PerfEventArray(perf_event_output_page_exp));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}

PerfEventArray::~PerfEventArray() {}

std::size_t PerfEventArray::memoryUsage() const {
  return d->processor_count * d->single_perf_event_output_size;
}

int PerfEventArray::fd() const { return d->perf_event_array_map->fd(); }

bool PerfEventArray::read(BufferList &buffer_list,
                          std::size_t &read_error_count,
                          std::size_t &lost_event_count,
                          const std::chrono::milliseconds &timeout) {
  buffer_list.clear();

  read_error_count = 0U;
  lost_event_count = 0U;

  auto error = ::poll(d->perf_event_output_pollfd.data(),
                      d->perf_event_output_pollfd.size(),
                      static_cast<int>(timeout.count()));

  if (error < 0) {
    if (errno == EINTR) {
      return true;
    }

    return false;

  } else if (error == 0) {
    return true;
  }

  for (auto processor_index = 0U;
       processor_index < d->perf_event_output_pollfd.size();
       ++processor_index) {

    auto &poll_fd = d->perf_event_output_pollfd.at(processor_index);
    if ((poll_fd.revents & POLLIN) == 0) {
      continue;
    }

    poll_fd.revents = 0;

    auto perf_buffer_list = readPerfMemory(processor_index);
    if (perf_buffer_list.empty()) {
      continue;
    }

    for (const auto &perf_buffer : perf_buffer_list) {
      if (perf_buffer.size() < sizeof(struct perf_event_header)) {
        ++read_error_count;
        continue;
      }

      struct perf_event_header event_header;
      std::memcpy(&event_header, perf_buffer.data(), sizeof(event_header));

      if (event_header.type == PERF_RECORD_LOST) {
        // TODO: We can read how many records we lost here
        ++lost_event_count;
        continue;

      } else if (event_header.type != PERF_RECORD_SAMPLE) {
        ++read_error_count;
        continue;
      }

      if (sizeof(struct perf_event_header) + 4U > perf_buffer.size()) {
        ++read_error_count;
        continue;
      }

      auto perf_record_size_ptr = perf_buffer.data() + sizeof(event_header);

      std::uint32_t perf_record_size;
      std::memcpy(&perf_record_size, perf_record_size_ptr,
                  sizeof(perf_record_size));

      if (perf_record_size > perf_buffer.size() - sizeof(event_header)) {
        ++read_error_count;
        continue;
      }

      buffer_list.push_back(std::move(perf_buffer));
    }
  }

  return true;
}

PerfEventArray::PerfEventArray(std::size_t perf_event_output_page_exp)
    : d(new PrivateData) {

  auto page_count =
      static_cast<std::size_t>(1 + std::pow(2, perf_event_output_page_exp));

  d->single_perf_event_output_size =
      static_cast<std::size_t>(getpagesize()) * page_count;

  auto perf_event_array_map_exp = PerfEventArrayMap::create(128U);
  if (!perf_event_array_map_exp.succeeded()) {
    throw perf_event_array_map_exp.error();
  }

  d->perf_event_array_map = perf_event_array_map_exp.takeValue();
  d->processor_count = static_cast<std::size_t>(get_nprocs_conf());

  for (auto cpu_index = 0U; cpu_index < d->processor_count; ++cpu_index) {
    auto perf_event_output_exp = createPerfEventOutputForCPU(
        cpu_index, d->single_perf_event_output_size);

    if (!perf_event_output_exp.succeeded()) {
      throw perf_event_output_exp.error();
    }

    auto perf_event_output = perf_event_output_exp.takeValue();

    auto err =
        d->perf_event_array_map->set(cpu_index, perf_event_output.fd.get());

    if (!err.succeeded()) {
      throw StringError::create("Failed to populate the perf event array map");
    }

    struct pollfd poll_fd = {};
    poll_fd.fd = perf_event_output.fd.get();
    poll_fd.events = POLLIN;
    d->perf_event_output_pollfd.push_back(std::move(poll_fd));
    d->perf_event_output_list.insert({cpu_index, std::move(perf_event_output)});
  }
}

PerfEventArray::BufferList
PerfEventArray::readPerfMemory(std::size_t processor_index) {
  BufferList buffer_list;

  if (processor_index > d->perf_event_output_list.size()) {
    return buffer_list;
  }

  auto &perf_event_output = d->perf_event_output_list.at(processor_index);
  auto perf_header_memory = perf_event_output.memory->pointer();

  std::uint64_t data_size{0U};
  std::memcpy(&data_size, perf_header_memory + kPerfDataSizeOffset,
              sizeof(data_size));

  std::uint64_t data_offset{0U};
  std::memcpy(&data_offset, perf_header_memory + kPerfDataOffsetOffset,
              sizeof(data_offset));

  auto perf_data_memory = perf_header_memory + data_offset;

  for (;;) {
    std::uint64_t data_tail{0U};
    std::memcpy(&data_tail, perf_header_memory + kPerfDataTailOffset,
                sizeof(data_tail));

    std::uint64_t data_head{0U};
    std::memcpy(&data_head, perf_header_memory + kPerfDataHeadOffset,
                sizeof(data_head));

    if (data_tail == data_head) {
      break;
    }

    auto event_data_start = perf_data_memory + (data_tail % data_size);

    struct perf_event_header event_header;
    std::memcpy(&event_header, event_data_start, sizeof(event_header));

    auto event_data_end =
        perf_data_memory + ((data_tail + event_header.size) % data_size);

    auto buffer = std::vector<std::uint8_t>(event_header.size);

    if (event_data_end < event_data_start) {
      auto bytes_until_wrap = static_cast<std::size_t>(
          (perf_data_memory + data_size) - event_data_start);

      std::memcpy(buffer.data(), event_data_start, bytes_until_wrap);
      std::memcpy(buffer.data() + bytes_until_wrap, perf_data_memory,
                  event_header.size - bytes_until_wrap);

    } else {
      std::memcpy(buffer.data(), event_data_start, event_header.size);
    }

    buffer_list.push_back(std::move(buffer));

    data_tail += event_header.size;
    std::memcpy(perf_header_memory + kPerfDataTailOffset, &data_tail,
                sizeof(data_tail));
  }

  return buffer_list;
}
} // namespace tob::ebpf
