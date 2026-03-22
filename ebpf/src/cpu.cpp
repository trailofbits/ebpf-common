/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include <tob/ebpf/cpu.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace tob::ebpf {

namespace {

const std::string kPossibleCpuPseudoFile{"/sys/devices/system/cpu/possible"};
const std::string kOnlineCpuPseudoFile{"/sys/devices/system/cpu/online"};

std::size_t getPossibleProcessorCountHelper() {
  std::ifstream cpu_info_file(kPossibleCpuPseudoFile);
  if (!cpu_info_file) {
    throw std::runtime_error("Failed to open the following file: " +
                             kPossibleCpuPseudoFile);
  }

  std::string cpu_info;
  std::getline(cpu_info_file, cpu_info);
  if (!cpu_info_file || cpu_info.empty()) {
    throw std::runtime_error("Failed to read the following file: " +
                             kPossibleCpuPseudoFile);
  }

  if (cpu_info == "0") {
    return 1U;
  }

  auto separator = cpu_info.find('-');
  if (separator == std::string::npos) {
    throw std::runtime_error(
        "Failed to find the range separator in the following file: " +
        kPossibleCpuPseudoFile);
  }

  auto cpu_count_index = separator + 1;
  if (cpu_count_index >= cpu_info.size()) {
    throw std::runtime_error(
        "The following file is not written in a supported format: " +
        kPossibleCpuPseudoFile);
  }

  auto string_ptr = cpu_info.data() + cpu_count_index;

  char *null_terminator{nullptr};
  auto possible_cpu_count = std::strtoull(string_ptr, &null_terminator, 10);
  if (possible_cpu_count == 0 || null_terminator == nullptr ||
      *null_terminator != 0) {

    throw std::runtime_error(
        "Failed to parse the CPU range value in the following file: " +
        kPossibleCpuPseudoFile);
  }

  return possible_cpu_count + 1;
}

} // namespace

std::size_t getPossibleProcessorCount() {
  static const auto kPossibleProcessorCount = getPossibleProcessorCountHelper();

  return kPossibleProcessorCount;
}

std::vector<std::size_t> parseCpuList(const std::string &cpu_list_str) {
  std::vector<std::size_t> cpu_list;
  std::istringstream stream(cpu_list_str);
  std::string token;

  while (std::getline(stream, token, ',')) {
    auto dash = token.find('-');
    if (dash == std::string::npos) {
      char *end{nullptr};
      auto cpu = std::strtoull(token.c_str(), &end, 10);
      if (end == nullptr || *end != '\0') {
        throw std::runtime_error("Failed to parse CPU value: " + token);
      }

      cpu_list.push_back(static_cast<std::size_t>(cpu));
    } else {
      auto start_str = token.substr(0, dash);
      auto end_str = token.substr(dash + 1);

      char *end{nullptr};
      auto range_start = std::strtoull(start_str.c_str(), &end, 10);
      if (end == nullptr || *end != '\0') {
        throw std::runtime_error("Failed to parse CPU range start: " +
                                 start_str);
      }

      auto range_end = std::strtoull(end_str.c_str(), &end, 10);
      if (end == nullptr || *end != '\0') {
        throw std::runtime_error("Failed to parse CPU range end: " + end_str);
      }

      for (auto i = range_start; i <= range_end; ++i) {
        cpu_list.push_back(static_cast<std::size_t>(i));
      }
    }
  }

  return cpu_list;
}

std::vector<std::size_t> getOnlineProcessorList() {
  std::ifstream cpu_info_file(kOnlineCpuPseudoFile);
  if (!cpu_info_file) {
    throw std::runtime_error("Failed to open the following file: " +
                             kOnlineCpuPseudoFile);
  }

  std::string cpu_info;
  std::getline(cpu_info_file, cpu_info);
  if (!cpu_info_file || cpu_info.empty()) {
    throw std::runtime_error("Failed to read the following file: " +
                             kOnlineCpuPseudoFile);
  }

  return parseCpuList(cpu_info);
}
} // namespace tob::ebpf