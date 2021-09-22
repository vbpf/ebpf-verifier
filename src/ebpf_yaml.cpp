// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <iostream>
#include <variant>

#include <yaml-cpp/yaml.h>

#include "asm_parse.hpp"
#include "asm_ostream.hpp"
#include "ebpf_verifier.hpp"
#include "ebpf_yaml.hpp"
#include "string_constraints.hpp"

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

static EbpfProgramType make_progran_type(const std::string& name, ebpf_context_descriptor_t* context_descriptor) {
    return EbpfProgramType{
        .name=name,
        .context_descriptor=context_descriptor,
        .platform_specific_data=0,
        .section_prefixes={},
        .is_privileged=false
    };
}

static std::set<std::string> vector_to_set(const std::vector<std::string>& s) {
    std::set<std::string> res;
    for (const auto& item : s)
        res.insert(item);
    return res;
}

static string_invariant read_invariant(const std::vector<std::string>& raw_invariant) {
    std::set<std::string> res = vector_to_set(raw_invariant);
    if (res == std::set<std::string>{"_|_"})
        return string_invariant{};
    return string_invariant{res};
}

struct RawTestCase {
    std::string test_case;
    std::vector<std::string> pre;
    std::vector<std::tuple<std::string, std::vector<std::string>>> raw_blocks;
    std::vector<std::string> post;
};

static std::vector<std::string> parse_block(const YAML::Node& block_node) {
    std::vector<std::string> block;
    std::istringstream is{block_node.as<std::string>()};
    std::string line;
    while (std::getline(is, line))
        block.emplace_back(line);
    return block;
}

static auto parse_code(const YAML::Node& code_node) {
    std::vector<std::tuple<std::string, std::vector<std::string>>> res;
    for (const auto& item : code_node) {
        res.emplace_back(item.first.as<std::string>(), parse_block(item.second));
    }
    return res;
}

static RawTestCase parse_case(const YAML::Node& case_node) {
    return RawTestCase {
        .test_case = case_node["test-case"].as<std::string>(),
        .pre = case_node["pre"].as<std::vector<std::string>>(),
        .raw_blocks = parse_code(case_node["code"]),
        .post = case_node["post"].as<std::vector<std::string>>(),
    };
}

static InstructionSeq raw_cfg_to_instruction_seq(const std::vector<std::tuple<std::string, std::vector<std::string>>>& raw_blocks) {
    std::map<std::string, crab::label_t> label_name_to_label;

    int label_index = 0;
    for (const auto& [label_name, raw_block] : raw_blocks) {
        label_name_to_label.emplace(label_name, label_index);
        // don't count large instructions as 2
        label_index += raw_block.size();
    }

    InstructionSeq res;
    label_index = 0;
    for (const auto& [label_name, raw_block] : raw_blocks) {
        for (const std::string& line: raw_block) {
            const Instruction& ins = parse_instruction(line, label_name_to_label);
            if (std::holds_alternative<Undefined>(ins))
                std::cout << "text:" << line << "; ins: " << ins << "\n";
            res.emplace_back(label_index, ins);
            label_index++;
        }
    }
    return res;
}

static TestCase read_case(const RawTestCase& raw_case) {
    return TestCase{
        .name = raw_case.test_case,
        .assumed_pre_invariant = read_invariant(raw_case.pre),
        .instruction_seq = raw_cfg_to_instruction_seq(raw_case.raw_blocks),
        .expected_post_invariant = read_invariant(raw_case.post),
    };
}

static std::vector<TestCase> read_suite(const std::string& path) {
    std::ifstream f{path};
    std::vector<TestCase> res;
    for (const YAML::Node& config : YAML::LoadAll(f)) {
        res.push_back(read_case(parse_case(config)));
    }
    return res;
}


std::optional<Failure> run_yaml_test_case(const TestCase& test_case) {
    ebpf_context_descriptor_t context_descriptor{0, -1, -1, -1};
    EbpfProgramType program_type = make_progran_type(test_case.name, &context_descriptor);

    program_info info{&g_platform_test, {}, program_type};
    const auto& [db, pre_invs, post_invs] = ebpf_analyze_program_for_test(test_case.instruction_seq,
                                                                             test_case.assumed_pre_invariant,
                                                                             info, true, false);
    const auto& actual_last_invariant = pre_invs.at(label_t::exit);
    if (actual_last_invariant == test_case.expected_post_invariant && db.total_warnings == 0)
        return {};
    return Failure{
        .expected_but_unseen = test_case.expected_post_invariant - actual_last_invariant,
        .seen_but_not_expected = actual_last_invariant - test_case.expected_post_invariant,
        .db = db
    };
}

bool all_suites(const std::string& path) {
    bool result = true;
    for (const TestCase& test_case: read_suite(path)) {
        result = result && bool(run_yaml_test_case(test_case));
    }
    return result;
}

void foreach_suite(const std::string& path, const std::function<void(const TestCase&)>& f) {
    for (const TestCase& test_case: read_suite(path)) {
        f(test_case);
    }
}