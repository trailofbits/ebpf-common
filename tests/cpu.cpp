/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include <doctest/doctest.h>

#include <tob/ebpf/cpu.h>

namespace tob::ebpf {
TEST_CASE("parseCpuList") {
  SUBCASE("Single CPU 0") {
    auto result = parseCpuList("0");
    REQUIRE(result.size() == 1);
    REQUIRE(result[0] == 0);
  }

  SUBCASE("Single CPU non-zero") {
    auto result = parseCpuList("5");
    REQUIRE(result.size() == 1);
    REQUIRE(result[0] == 5);
  }

  SUBCASE("Simple range") {
    auto result = parseCpuList("0-3");
    REQUIRE(result.size() == 4);
    REQUIRE(result[0] == 0);
    REQUIRE(result[1] == 1);
    REQUIRE(result[2] == 2);
    REQUIRE(result[3] == 3);
  }

  SUBCASE("Multiple individual CPUs") {
    auto result = parseCpuList("0,2,4");
    REQUIRE(result.size() == 3);
    REQUIRE(result[0] == 0);
    REQUIRE(result[1] == 2);
    REQUIRE(result[2] == 4);
  }

  SUBCASE("Mixed ranges and singles") {
    auto result = parseCpuList("0-3,5,7-9");
    REQUIRE(result.size() == 8);
    REQUIRE(result[0] == 0);
    REQUIRE(result[1] == 1);
    REQUIRE(result[2] == 2);
    REQUIRE(result[3] == 3);
    REQUIRE(result[4] == 5);
    REQUIRE(result[5] == 7);
    REQUIRE(result[6] == 8);
    REQUIRE(result[7] == 9);
  }

  SUBCASE("Large range") {
    auto result = parseCpuList("0-127");
    REQUIRE(result.size() == 128);
    REQUIRE(result[0] == 0);
    REQUIRE(result[127] == 127);
  }

  SUBCASE("Non-contiguous ranges with gaps") {
    auto result = parseCpuList("0-1,4-5,8-9");
    REQUIRE(result.size() == 6);
    REQUIRE(result[0] == 0);
    REQUIRE(result[1] == 1);
    REQUIRE(result[2] == 4);
    REQUIRE(result[3] == 5);
    REQUIRE(result[4] == 8);
    REQUIRE(result[5] == 9);
  }
}
} // namespace tob::ebpf
