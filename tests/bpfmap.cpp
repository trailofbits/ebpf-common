/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include <cstdint>

#include <doctest/doctest.h>

#include <tob/ebpf/bpfmap.h>

namespace tob::ebpf {
namespace {
using TestBPFHashMap = BPFMap<BPF_MAP_TYPE_HASH, std::uint32_t>;

const std::size_t kHashMapSize{32U};
const std::size_t kValueSize{4U};

TestBPFHashMap::Ref bpf_hash_map;
const std::vector<std::uint8_t> kTestValue(kValueSize, 0xFFU);
} // namespace

TEST_CASE("Setting values") {
  if (!bpf_hash_map) {
    auto bpf_hash_map_exp = TestBPFHashMap::create(kValueSize, kHashMapSize);
    REQUIRE(bpf_hash_map_exp.succeeded());

    bpf_hash_map = bpf_hash_map_exp.takeValue();
  }

  SUBCASE("Setting values") {
    for (std::uint32_t i = 0; i < kHashMapSize; ++i) {
      auto err = bpf_hash_map->set(i, kTestValue);
      REQUIRE(err.value() == BPFMapErrorCode::Value::Success);
      REQUIRE(err.succeeded());
    }
  }

  SUBCASE("Retrieving existing values") {
    for (std::uint32_t i = 0; i < kHashMapSize; ++i) {
      std::vector<std::uint8_t> value;
      auto err = bpf_hash_map->get(value, i);

      REQUIRE(err.value() == BPFMapErrorCode::Value::Success);
      REQUIRE(err.succeeded());

      REQUIRE(value == kTestValue);
    }
  }

  SUBCASE("Removing existing values") {
    for (std::uint32_t i = 0; i < kHashMapSize; ++i) {
      auto err = bpf_hash_map->erase(i);

      REQUIRE(err.value() == BPFMapErrorCode::Value::Success);
      REQUIRE(err.succeeded());
    }
  }

  SUBCASE("Retrieving inexisting values") {
    for (std::uint32_t i = 0; i < kHashMapSize; ++i) {
      std::vector<std::uint8_t> value;
      auto err = bpf_hash_map->get(value, i);

      REQUIRE(err.value() == BPFMapErrorCode::Value::NotFound);
      REQUIRE(err.succeeded());

      REQUIRE(value.size() == kValueSize);
    }
  }

  SUBCASE("Removing inexisting values") {
    for (std::uint32_t i = 0; i < kHashMapSize; ++i) {
      auto err = bpf_hash_map->erase(i);

      REQUIRE(err.value() == BPFMapErrorCode::Value::NotFound);
      REQUIRE(err.succeeded());
    }
  }
}
} // namespace tob::ebpf
