// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <fstream>
#include <iostream>

#include "yaml-cpp/yaml.h"

#include "asm_parse.hpp"
#include "asm_ostream.hpp"
#include "ebpf_verifier.hpp"

static EbpfProgramType ebpf_get_program_type(const std::string& section, const std::string& path) {
    return {};
}

static EbpfMapType ebpf_get_map_type(uint32_t platform_specific_type) {
    return {};
}

static EbpfHelperPrototype ebpf_get_helper_prototype(int32_t n) {
    return {};
};

static bool ebpf_is_helper_usable(int32_t n){
    return false;
};

static void ebpf_parse_maps_section(std::vector<EbpfMapDescriptor>& map_descriptors, const char* data, size_t size,
                                    const struct ebpf_platform_t* platform, ebpf_verifier_options_t options) {
}

static EbpfMapDescriptor test_map_descriptor = {
    .original_fd=0,
    .type=0,
    .key_size=0,
    .value_size=0,
    .max_entries=0,
    .inner_map_fd=0
};

static EbpfMapDescriptor& ebpf_get_map_descriptor(int map_fd) { return test_map_descriptor; }

ebpf_platform_t g_platform_test = {
    .get_program_type = ebpf_get_program_type,
    .get_helper_prototype = ebpf_get_helper_prototype,
    .is_helper_usable = ebpf_is_helper_usable,
    .map_record_size = 0,
    .parse_maps_section = ebpf_parse_maps_section,
    .get_map_descriptor = ebpf_get_map_descriptor,
    .get_map_type = ebpf_get_map_type
};

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
        ebpf_context_descriptor_t context_descriptor{0, -1, -1, -1};
        EbpfProgramType program_type{
            .name=config["test-case"].as<std::string>(),
            .context_descriptor=&context_descriptor,
            .platform_specific_data=0,
            .section_prefixes={},
            .is_privileged=false
        };
        program_info info{&g_platform_test, {}, program_type};
        const auto& [stats, pre_invs, post_invs] = ebpf_analyze_program_for_test(prog, info, true, false);
        const auto& last_invariant = post_invs.at(last_label);
        if (last_invariant) {
            for (const std::string& cst : *last_invariant)
                std::cout << cst << "\n";
        }
        std::cout << "---\n\n";
    }
}