// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <catch2/catch_all.hpp>

#include "ebpf_verifier.hpp"
#include "ebpf_yaml.hpp"

// TODO: move out of this framework

#define YAML_CASE(path) \
    TEST_CASE("YAML suite: " path, "[yaml]") { \
        foreach_suite(path, [&](const TestCase& test_case){ \
            std::optional<Failure> failure = run_yaml_test_case(test_case); \
            if (failure) { \
                std::cout << "test case: " << test_case.name << "\n"; \
                print_failure(*failure, std::cout); \
            } \
            REQUIRE(!failure); \
        }); \
    }

YAML_CASE("test-data/add.yaml")
YAML_CASE("test-data/assign.yaml")
YAML_CASE("test-data/bitop.yaml")
YAML_CASE("test-data/call.yaml")
YAML_CASE("test-data/divmod.yaml")
YAML_CASE("test-data/full64.yaml")
YAML_CASE("test-data/jump.yaml")
YAML_CASE("test-data/packet.yaml")
YAML_CASE("test-data/parse.yaml")
YAML_CASE("test-data/shift.yaml")
YAML_CASE("test-data/stack.yaml")
YAML_CASE("test-data/subtract.yaml")
YAML_CASE("test-data/unop.yaml")
YAML_CASE("test-data/unsigned.yaml")
