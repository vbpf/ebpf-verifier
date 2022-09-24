// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once
#include <functional>
#include <string>
#include <set>

#include "crab_verifier.hpp"

struct TestCase {
    std::string name;
    string_invariant assumed_pre_invariant;
    InstructionSeq instruction_seq;
    string_invariant expected_post_invariant;
    std::set<std::string> expected_messages;
};

void foreach_suite(const std::string& path, const std::function<void(const TestCase&)>& f);
bool all_suites(const std::string& path);

template<typename T>
struct Diff {
    T unexpected;
    T unseen;
};

struct Failure {
    Diff<string_invariant> invariant;
    Diff<std::set<std::string>> messages;
};

void print_failure(const Failure& failure, std::ostream& out);

std::optional<Failure> run_yaml_test_case(const TestCase& test_case);

bool run_yaml(const std::string& path);
