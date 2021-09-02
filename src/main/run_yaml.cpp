// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <fstream>
#include <iostream>

#include "yaml-cpp/yaml.h"

#include "asm_parse.hpp"
#include "asm_ostream.hpp"

int main() {
    std::ifstream f{"test-data/single-instruction-assignment.yaml"};
    std::vector<YAML::Node> documents = YAML::LoadAll(f);

    for (const YAML::Node& config : documents) {
        std::cout << config["test-case"].as<std::string>() << "\n";

        std::cout << config["pre"].as<std::string>() << "\n";

        const std::string& code = config["code"].as<std::string>();
        const InstructionSeq& instruction_seq = parse_unlabeled_program(code);
        print(instruction_seq, std::cout, {});

        std::cout << config["post"].as<std::string>() << "\n";
        std::cout << "---\n\n";
    }
}