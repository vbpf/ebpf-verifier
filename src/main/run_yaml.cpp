// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <iostream>

#include "CLI11.hpp"

#include "ebpf_verifier.hpp"
#include "ebpf_yaml.hpp"

int main(int argc, char** argv) {
    CLI::App app{"Run yaml test cases"};

    std::string filename;
    app.add_option("path", filename, "YAML file.")->required()->type_name("FILE");
    CLI11_PARSE(app, argc, argv);
    bool res = true;
    foreach_suite(filename, [&](const TestCase& test_case) {
        std::cout << test_case.name << ": " << std::flush;
        if (const auto& maybe_failure = run_yaml_test_case(test_case)) {
            std::cout << "+" << maybe_failure->seen_but_not_expected << "\n";
            std::cout << "-" << maybe_failure->expected_but_unseen << "\n";
            res = false;
            std::cout << "failed\n";
        } else {
            std::cout << "pass\n";
        }
    });
    return !res;
}
