// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once
#include <functional>
#include <set>
#include <string>

#include "crab_verifier.hpp"

struct TestCase {
    std::string name;
    ebpf_verifier_options_t options{};
    string_invariant assumed_pre_invariant;
    InstructionSeq instruction_seq;
    string_invariant expected_post_invariant;
    std::set<std::string> expected_messages;
};

void foreach_suite(const std::string& path, const std::function<void(const TestCase&)>& f);
bool all_suites(const std::string& path);

template <typename T>
struct Diff {
    T unexpected;
    T unseen;
};

struct Failure {
    Diff<string_invariant> invariant;
    Diff<std::set<std::string>> messages;
};

void print_failure(const Failure& failure, std::ostream& os = std::cout);

std::optional<Failure> run_yaml_test_case(TestCase test_case, bool debug = false);

struct ConformanceTestResult {
    bool success{};
    crab::interval_t r0_value = crab::interval_t::top();
};

ConformanceTestResult run_conformance_test_case(const std::vector<std::byte>& memory_bytes,
                                                const std::vector<std::byte>& program_bytes, bool debug);

bool run_yaml(const std::string& path);
