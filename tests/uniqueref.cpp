/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include <doctest/doctest.h>

#include <tob/utils/uniqueref.h>

namespace tob::utils {
namespace {
std::size_t dealloc_count{0U};

struct TestDeleter final {
  using Reference = int;
  static const Reference kNullReference{-1};

  void operator()(Reference x) const {
    if (x == kNullReference) {
      return;
    }

    ++dealloc_count;
  }
};

using UniqueRefTest = UniqueRef<TestDeleter>;
} // namespace

TEST_CASE("Custom deleter") {
  SUBCASE("Must not be copyable") {
    REQUIRE(std::is_copy_constructible<UniqueRefTest>::value == 0);
    REQUIRE(std::is_trivially_copy_constructible<UniqueRefTest>::value == 0);
    REQUIRE(std::is_nothrow_copy_constructible<UniqueRefTest>::value == 0);

    REQUIRE(std::is_copy_assignable<UniqueRefTest>::value == 0);
    REQUIRE(std::is_trivially_copy_assignable<UniqueRefTest>::value == 0);
    REQUIRE(std::is_nothrow_copy_assignable<UniqueRefTest>::value == 0);
  }

  SUBCASE("Empty UniqueRef, going out of scope") {
    dealloc_count = 0U;

    { UniqueRefTest obj; }

    REQUIRE(dealloc_count == 0U);
  }

  SUBCASE("Valid UniqueRef, going out of scope") {
    dealloc_count = 0U;

    { UniqueRefTest obj(1); }

    REQUIRE(dealloc_count == 1U);
  }

  SUBCASE("Reset UniqueRef, going out of scope") {
    dealloc_count = 0U;

    {
      UniqueRefTest obj;
      obj.reset(1);
    }

    REQUIRE(dealloc_count == 1U);
  }

  SUBCASE("Reset UniqueRef with null value, going out of scope") {
    dealloc_count = 0U;

    {
      UniqueRefTest obj;
      obj.reset(-1);
    }

    REQUIRE(dealloc_count == 0U);
  }

  SUBCASE("Reset UniqueRef, multiple times") {
    dealloc_count = 0U;

    {
      UniqueRefTest obj;
      obj.reset(1);
      obj.reset(2);
      obj.reset(4);
      obj.reset(5);

      REQUIRE(dealloc_count == 3U);
    }

    REQUIRE(dealloc_count == 4U);
  }

  SUBCASE("Move assignment") {
    dealloc_count = 0U;

    UniqueRefTest obj;

    {
      UniqueRefTest original(1);

      UniqueRefTest move1 = std::move(original);
      UniqueRefTest move2 = std::move(move1);
      UniqueRefTest move3 = std::move(move2);

      obj = std::move(move3);
    }

    REQUIRE(dealloc_count == 0U);

    obj.reset();

    REQUIRE(dealloc_count == 1U);
  }

  SUBCASE("Move constructor") {
    dealloc_count = 0U;

    UniqueRefTest obj;

    {
      UniqueRefTest original(1);

      UniqueRefTest move1(std::move(original));
      UniqueRefTest move2(std::move(move1));
      UniqueRefTest move3(std::move(move2));

      obj = std::move(move3);
    }

    REQUIRE(dealloc_count == 0U);

    obj.reset();

    REQUIRE(dealloc_count == 1U);
  }
}
} // namespace tob::utils
