// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once
#include <string>
#include <functional>

struct TestCase;

void foreach_suite(const std::string& path, std::function<void(const TestCase&)> f);
bool all_suites(const std::string& path);

bool run_yaml_test_case(const TestCase& test_case);

bool run_yaml(const std::string& path);
