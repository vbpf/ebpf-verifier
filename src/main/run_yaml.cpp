// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <fstream>
#include <iostream>

#include "yaml-cpp/yaml.h"

#include "asm_parse.hpp"
#include "asm_ostream.hpp"
#include "ebpf_verifier.hpp"

int main() {
    std::ifstream f{"test-data/single-instruction-assignment.yaml"};
    std::vector<YAML::Node> documents = YAML::LoadAll(f);

    for (const YAML::Node& config : documents) {
        std::cout << config["test-case"].as<std::string>() << "\n";

        std::cout << config["pre"].as<std::string>() << "\n";

        const std::string& code = config["code"].as<std::string>();
        InstructionSeq prog = parse_unlabeled_program(code);
        assert(!prog.empty());
        print(prog, std::cout, {});

        const auto [last_label, last_instruction] = prog.back();
        prog.emplace_back(label_t(last_label.from + 1), Exit());
        const ebpf_platform_t* platform = &g_ebpf_platform_linux;
        ebpf_context_descriptor_t context_descriptor{0, -1, -1, -1};
        EbpfProgramType program_type{
            .name=config["test-case"].as<std::string>(),
            .context_descriptor=&context_descriptor,
            .platform_specific_data=0,
            .section_prefixes={},
            .is_privileged=false
        };
        program_info info{platform, {}, program_type};
        ebpf_verifier_options_t options = ebpf_verifier_default_options;
        options.no_simplify = true;
        const auto& [db, pre_invariants, post_invariants] = ebpf_verify_program(prog, info, &options);
        const auto& last_invariant = post_invariants.at(last_label);
        if (last_invariant) {
            for (const std::string& cst : *last_invariant)
                std::cout << cst << "\n";
        }
        std::cout << "---\n\n";
    }
}