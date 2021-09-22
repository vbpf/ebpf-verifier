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

    bool verbose = false;
    app.add_flag("-v", verbose, "Verbose");

    bool quiet = false;
    app.add_flag("-q", quiet, "Never print code");

    CLI11_PARSE(app, argc, argv);
    bool res = true;
    foreach_suite(filename, [&](const TestCase& test_case) {
        std::cout << test_case.name << ": " << std::flush;
        const auto& maybe_failure = run_yaml_test_case(test_case);
        if (!quiet && (verbose || maybe_failure)) {
            std::cout << "\n";
            std::cout << "Pre-invariant: " << test_case.assumed_pre_invariant << "\n";
            print(test_case.instruction_seq, std::cout, {});
            std::cout << "Expected post-invariant: " << test_case.expected_post_invariant << "\n";
        }
        if (maybe_failure) {
            std::cout << "\n";
            std::cout << "Unexpected: " << maybe_failure->seen_but_not_expected << "\n";
            std::cout << "Unseen: " << maybe_failure->expected_but_unseen << "\n";
            res = false;
            for (const auto& [label, items]: maybe_failure->db.m_db) {
                std::cout << label << ": ";
                for (const auto& item : items)
                    std::cout << item << "\n";
            }
            std::cout << "failed\n";
        } else {
            std::cout << "pass\n";
        }
    });
    return !res;
}
