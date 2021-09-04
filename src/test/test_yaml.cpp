// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "catch.hpp"

#include "ebpf_verifier.hpp"
#include "ebpf_yaml.hpp"

TEST_CASE("YAML suite: single-instruction-assignment", "[yaml]") {
    // TODO: move out of this framework
    foreach_suite("test-data/single-instruction-assignment.yaml", [&](const TestCase& test_case){
        REQUIRE(run_yaml_test_case(test_case));
    });
}
