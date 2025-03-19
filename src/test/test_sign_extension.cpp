// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <catch2/catch_all.hpp>

#include <algorithm>
#include <cstdint>

#include "crab/interval.hpp"

using crab::interval_t;

TEST_CASE("sign_extend 1 bit [0, 0]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'0, 0b0'0}.sign_extend(1) == interval_t{0, 0});
}

TEST_CASE("sign_extend 1 bit [0, 1]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'0, 0b0'1}.sign_extend(1) == interval_t{-1, 0});
}

TEST_CASE("sign_extend 1 bit [1, 1]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'1, 0b0'1}.sign_extend(1) == interval_t{-1, -1});
}

// === 2 bits ===

TEST_CASE("sign_extend 2 bits [0, 0]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'00, 0b0'00}.sign_extend(2) == interval_t{0, 0});
}

TEST_CASE("sign_extend 2 bits [0, 1]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'00, 0b0'01}.sign_extend(2) == interval_t{0, 1});
}

TEST_CASE("sign_extend 2 bits [0, 2]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'00, 0b0'10}.sign_extend(2) == interval_t{-2, 1});
}

TEST_CASE("sign_extend 2 bits [0, 3]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'00, 0b0'11}.sign_extend(2) == interval_t{-2, 1});
}

TEST_CASE("sign_extend 2 bits [1, 1]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'01, 0b0'01}.sign_extend(2) == interval_t{1, 1});
}

TEST_CASE("sign_extend 2 bits [1, 2]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'01, 0b0'10}.sign_extend(2) == interval_t{-2, 1});
}

TEST_CASE("sign_extend 2 bits [1, 3]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'01, 0b0'11}.sign_extend(2) == interval_t{-2, 1});
}

TEST_CASE("sign_extend 2 bits [2, 2]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'10, 0b0'10}.sign_extend(2) == interval_t{-2, -2});
}

TEST_CASE("sign_extend 2 bits [2, 3]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'10, 0b0'11}.sign_extend(2) == interval_t{-2, -1});
}

TEST_CASE("sign_extend 2 bit [3, 3]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'11, 0b0'11}.sign_extend(2) == interval_t{-1, -1});
}

// === 3 bits ===

TEST_CASE("sign_extend 3 bits [0, 0]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'000, 0b0'000}.sign_extend(3) == interval_t{0, 0});
}

TEST_CASE("sign_extend 3 bits [0, 1]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'000, 0b0'001}.sign_extend(3) == interval_t{0, 1});
}

TEST_CASE("sign_extend 3 bits [0, 2]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'000, 0b0'010}.sign_extend(3) == interval_t{0, 2});
}

TEST_CASE("sign_extend 3 bits [0, 3]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'000, 0b0'011}.sign_extend(3) == interval_t{0, 3});
}

TEST_CASE("sign_extend 3 bits [0, 4]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'000, 0b0'100}.sign_extend(3) == interval_t{-4, 3});
}

TEST_CASE("sign_extend 3 bits [0, 5]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'000, 0b0'101}.sign_extend(3) == interval_t{-3, 3});
}

TEST_CASE("sign_extend 3 bits [0, 6]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'000, 0b0'110}.sign_extend(3) == interval_t{-2, 3});
}

TEST_CASE("sign_extend 3 bits [0, 7]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'000, 0b0'111}.sign_extend(3) == interval_t{-4, 3});
}

TEST_CASE("sign_extend 3 bits [1, 1]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'001, 0b0'001}.sign_extend(3) == interval_t{1, 1});
}

TEST_CASE("sign_extend 3 bits [1, 2]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'001, 0b0'010}.sign_extend(3) == interval_t{1, 2});
}

TEST_CASE("sign_extend 3 bits [1, 3]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'001, 0b0'011}.sign_extend(3) == interval_t{1, 3});
}

TEST_CASE("sign_extend 3 bits [1, 4]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'001, 0b0'100}.sign_extend(3) == interval_t{-4, 3});
}

TEST_CASE("sign_extend 3 bits [1, 5]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'001, 0b0'101}.sign_extend(3) == interval_t{-4, 3});
}

TEST_CASE("sign_extend 3 bits [1, 6]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'001, 0b0'110}.sign_extend(3) == interval_t{-4, 3});
}

TEST_CASE("sign_extend 3 bits [1, 7]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'001, 0b0'111}.sign_extend(3) == interval_t{-4, 3});
}

TEST_CASE("sign_extend 3 bits [2, 2]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'010, 0b0'010}.sign_extend(3) == interval_t{2, 2});
}

TEST_CASE("sign_extend 3 bits [2, 3]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'010, 0b0'011}.sign_extend(3) == interval_t{2, 3});
}

TEST_CASE("sign_extend 3 bits [2, 4]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'010, 0b0'100}.sign_extend(3) == interval_t{-4, 3});
}

TEST_CASE("sign_extend 3 bits [2, 5]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'010, 0b0'101}.sign_extend(3) == interval_t{-4, 3});
}

TEST_CASE("sign_extend 3 bits [2, 6]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'010, 0b0'110}.sign_extend(3) == interval_t{-4, 3});
}

TEST_CASE("sign_extend 3 bits [2, 7]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'010, 0b0'111}.sign_extend(3) == interval_t{-4, 3});
}

TEST_CASE("sign_extend 3 bits [3, 3]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'011, 0b0'011}.sign_extend(3) == interval_t{3, 3});
}

TEST_CASE("sign_extend 3 bits [3, 4]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'011, 0b0'100}.sign_extend(3) == interval_t{-4, 3});
}

TEST_CASE("sign_extend 3 bits [3, 5]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'011, 0b0'101}.sign_extend(3) == interval_t{-4, 3});
}

TEST_CASE("sign_extend 3 bits [3, 6]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'011, 0b0'110}.sign_extend(3) == interval_t{-4, 3});
}

TEST_CASE("sign_extend 3 bits [3, 7]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'011, 0b0'111}.sign_extend(3) == interval_t{-4, 3});
}

TEST_CASE("sign_extend 3 bits [4, 4]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'100, 0b0'100}.sign_extend(3) == interval_t{-4, -4});
}

TEST_CASE("sign_extend 3 bits [4, 5]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'100, 0b0'101}.sign_extend(3) == interval_t{-4, -3});
}

TEST_CASE("sign_extend 3 bits [4, 6]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'100, 0b0'110}.sign_extend(3) == interval_t{-4, -2});
}

TEST_CASE("sign_extend 3 bits [4, 7]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'100, 0b0'111}.sign_extend(3) == interval_t{-4, -1});
}

TEST_CASE("sign_extend 3 bits [5, 5]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'101, 0b0'101}.sign_extend(3) == interval_t{-3, -3});
}

TEST_CASE("sign_extend 3 bits [5, 6]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'101, 0b0'110}.sign_extend(3) == interval_t{-3, -2});
}

TEST_CASE("sign_extend 3 bits [5, 7]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'101, 0b0'111}.sign_extend(3) == interval_t{-3, -1});
}

TEST_CASE("sign_extend 3 bits [6, 6]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'110, 0b0'110}.sign_extend(3) == interval_t{-2, -2});
}

TEST_CASE("sign_extend 3 bits [6, 7]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'110, 0b0'111}.sign_extend(3) == interval_t{-2, -1});
}

TEST_CASE("sign_extend 3 bits [7, 7]", "[sign_extension]") {
    REQUIRE(interval_t{0b0'111, 0b0'111}.sign_extend(3) == interval_t{-1, -1});
}
