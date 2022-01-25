/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "ebpf/src/llvmbridge.h"

#include <doctest/doctest.h>

namespace tob::ebpf {

namespace {

// clang-format off
static const StructBTFType kIoam6TraceHdrStructure = {
  { "ioam6_trace_hdr" },
  8,
  {
    {
      { "namespace_id" },
      2619,
      0,
      std::nullopt,
    },

    {
      { "overflow" },
      11,
      18,
      { 1 }
    },

    {
      { "nodelen" },
      11,
      19,
      { 5 }
    },

    {
      { "remlen" },
      11,
      24,
      { 7 }
    },

    {
      std::nullopt,
      115362,
      32,
      std::nullopt,
    },

    {
      { "data" },
      3292,
      64,
      std::nullopt,
    },
  },
};
// clang-format on

} // namespace

TEST_CASE("LLVMBridge::parsePath") {
  auto opt_path_component_list =
      LLVMBridge::parsePath("first.second[0][1].third[2][3].fourth[0]");

  REQUIRE(opt_path_component_list.has_value());

  {
    const auto &path_component_list = opt_path_component_list.value();
    REQUIRE(path_component_list.size() == 4);

    CHECK(path_component_list[0].name == "first");
    CHECK(path_component_list[0].index_list.size() == 0);

    CHECK(path_component_list[1].name == "second");
    CHECK(path_component_list[1].index_list.size() == 2);
    CHECK(path_component_list[1].index_list[0] == 0);
    CHECK(path_component_list[1].index_list[1] == 1);

    CHECK(path_component_list[2].name == "third");
    CHECK(path_component_list[2].index_list.size() == 2);
    CHECK(path_component_list[2].index_list[0] == 2);
    CHECK(path_component_list[2].index_list[1] == 3);

    CHECK(path_component_list[3].name == "fourth");
    CHECK(path_component_list[3].index_list.size() == 1);
    CHECK(path_component_list[3].index_list[0] == 0);
  }

  opt_path_component_list =
      LLVMBridge::parsePath(" first.second[0][1].third[2][3].fourth[0]");

  CHECK(!opt_path_component_list.has_value());

  opt_path_component_list =
      LLVMBridge::parsePath("first .second[0][1].third[2][3].fourth[0]");

  CHECK(!opt_path_component_list.has_value());

  opt_path_component_list =
      LLVMBridge::parsePath("first.second [0][1].third[2][3].fourth[0]");

  CHECK(!opt_path_component_list.has_value());

  opt_path_component_list =
      LLVMBridge::parsePath("first.second[0] [1].third[2][3].fourth[0]");

  CHECK(!opt_path_component_list.has_value());

  opt_path_component_list =
      LLVMBridge::parsePath("first.second[0][1] .third[2][3].fourth[0]");

  CHECK(!opt_path_component_list.has_value());

  opt_path_component_list =
      LLVMBridge::parsePath("first.second[ 0][1].third[2][3].fourth[0]");

  CHECK(!opt_path_component_list.has_value());

  opt_path_component_list =
      LLVMBridge::parsePath("first.second[0 ][1].third[2][3].fourth[0]");

  CHECK(!opt_path_component_list.has_value());

  opt_path_component_list =
      LLVMBridge::parsePath("first!.second[0][1].third[2][3].fourth[0]");

  CHECK(!opt_path_component_list.has_value());

  opt_path_component_list =
      LLVMBridge::parsePath("first.second[0!][1].third[2][3].fourth[0]");

  CHECK(!opt_path_component_list.has_value());

  opt_path_component_list =
      LLVMBridge::parsePath("first.second[0][1].third[2][3].fourth[0] ");

  CHECK(!opt_path_component_list.has_value());

  opt_path_component_list = LLVMBridge::parsePath("[10]");
  REQUIRE(opt_path_component_list.has_value());

  {
    const auto &path_component_list = opt_path_component_list.value();
    REQUIRE(path_component_list.size() == 1);

    CHECK(path_component_list[0].name.empty());
    CHECK(path_component_list[0].index_list.size() == 1);
  }
}

} // namespace tob::ebpf
