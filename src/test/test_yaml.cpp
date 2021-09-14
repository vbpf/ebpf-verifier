// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "catch.hpp"

#include "ebpf_verifier.hpp"
#include "ebpf_yaml.hpp"

// TODO: move out of this framework

#define YAML_CASE(path) \
    TEST_CASE("YAML suite: " path, "[yaml]") { \
        foreach_suite(path, [&](const TestCase& test_case){ \
            std::optional<Failure> failure = run_yaml_test_case(test_case);\
            REQUIRE(!failure); \
        }); \
    }

YAML_CASE("test-data/single-instruction-assignment.yaml")
YAML_CASE("test-data/single-instruction-binop.yaml")
YAML_CASE("test-data/single-instruction-unop.yaml")
