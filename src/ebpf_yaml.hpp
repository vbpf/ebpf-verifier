// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once
#include <functional>
#include <string>

#include "crab_verifier.hpp"

struct TestCase {
    std::string name;
    string_invariant assumed_pre_invariant;
    InstructionSeq instruction_seq;
    string_invariant expected_post_invariant;
};

void foreach_suite(const std::string& path, const std::function<void(const TestCase&)>& f);
bool all_suites(const std::string& path);

struct Failure {
    string_invariant expected_but_unseen;
    string_invariant seen_but_not_expected;
};
std::optional<Failure> run_yaml_test_case(const TestCase& test_case);

bool run_yaml(const std::string& path);
