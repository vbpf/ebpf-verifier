// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

// This program reads BPF instructions from stdin and memory contents from
// the first argument. It then executes the BPF program and prints the
// value of r0 at the end of execution.
// The program is intended to be used with the bpf conformance test suite.

#include <iostream>
#include <sstream>
#include <optional>
#include <string>
#include <vector>
#include "CLI11.hpp"
#include "ebpf_verifier.hpp"
#include "ebpf_yaml.hpp"
using string = std::string;

/**
 * @brief Read in a string of hex bytes and return a vector of bytes.
 *
 * @param[in] input String containing hex bytes.
 * @return Vector of bytes.
 */
std::vector<uint8_t> base16_decode(const std::string& input) {
    std::vector<uint8_t> output;
    std::stringstream ss(input);
    std::string value;
    while (std::getline(ss, value, ' ')) {
        try {
            output.push_back(std::stoi(value, nullptr, 16));
        } catch (...) {
            // Ignore invalid values.
        }
    }
    return output;
}

/**
 * @brief This program reads BPF instructions from stdin and memory contents from
 * the first agument. It then executes the BPF program and prints the
 * value of r0 at the end of execution.
 */
int main(int argc, char** argv) {
    CLI::App app{"Check conformance"};
    bool debug = false;
    app.add_flag("--debug", debug, "Debug");
    std::string memory_string;
    app.add_option("--memory,memory", memory_string, "base16 memory bytes");
    std::string program_string;
    app.add_option("--program", program_string, "base16 program bytes");
    CLI11_PARSE(app, argc, argv);

    if (program_string.empty()) {
        std::getline(std::cin, program_string);
    }

    uint64_t r0_value;
    bool result = run_conformance_test_case(base16_decode(memory_string), base16_decode(program_string), &r0_value, debug);
    if (!result) {
        if (debug) {
            std::cerr << "Verification failed\n";
        }
        return 1;
    }

    // Print output so the conformance test suite can check it.
    std::cout << std::hex << r0_value << std::endl;

    return 0;
}
