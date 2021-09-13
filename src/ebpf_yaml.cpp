// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <iostream>

#include <yaml-cpp/yaml.h>

#include "asm_parse.hpp"
#include "asm_ostream.hpp"
#include "ebpf_verifier.hpp"
#include "ebpf_yaml.hpp"

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

static string_invariant read_invariant(const YAML::Node& node) {
    std::set<std::string> res = vector_to_set(node.as<std::vector<std::string>>());
    if (res == std::set<std::string>{"_|_"})
        return {};
    return res;
}

struct TestCase {
    std::string name;
    string_invariant assumed_pre_invariant;
    InstructionSeq prog;
    string_invariant expected_post_invariant;
};

static TestCase read_case(const YAML::Node& config) {
    const std::string& name = config["test-case"].as<std::string>();
    const std::string& raw_code = config["code"].as<std::string>();
    InstructionSeq prog = parse_unlabeled_program(raw_code);
    if (prog.empty()) throw std::runtime_error(std::string("Empty program for test case: ") + name);
    return TestCase{
        .name = name,
        .assumed_pre_invariant = read_invariant(config["pre"]),
        .prog = parse_unlabeled_program(raw_code),
        .expected_post_invariant = read_invariant(config["post"]),
    };
}

static std::vector<TestCase> read_suite(const std::string& path) {
    std::ifstream f{path};
    std::vector<YAML::Node> documents = YAML::LoadAll(f);
    std::vector<TestCase> res;
    for (const YAML::Node& config : documents) {
        res.push_back(read_case(config));
    }
    return res;
}

struct Failure {
    string_invariant expected_but_unseen;
    string_invariant seen_but_not_expected;
};

// return a-b, taking account potential optional-none
static std::set<std::string> set_diff(const string_invariant& a, const string_invariant& b) {
    if (!a) return {};
    std::set<std::string> res;
    for (const std::string& cst : *a) {
        if (!b || !b->count(cst))
            res.insert(cst);
    }
    return res;
}

static std::optional<Failure> process_results(const string_invariant& expected_post_invariant,
                                       const string_invariant& actual_last_invariant) {
    if (actual_last_invariant == expected_post_invariant)
        return {};
    return Failure{
        .expected_but_unseen = set_diff(expected_post_invariant, actual_last_invariant),
        .seen_but_not_expected = set_diff(actual_last_invariant, expected_post_invariant),
    };
}

bool run_yaml_test_case(const TestCase& test_case) {
    ebpf_context_descriptor_t context_descriptor{0, -1, -1, -1};
    EbpfProgramType program_type = make_progran_type(test_case.name, &context_descriptor);

    program_info info{&g_platform_test, {}, program_type};
    const auto& [stats, pre_invs, post_invs] = ebpf_analyze_program_for_test(test_case.prog,
                                                                             test_case.assumed_pre_invariant,
                                                                             info, true, false);
    const auto& actual_last_invariant = pre_invs.at(label_t::exit);
    const auto& failure = process_results(test_case.expected_post_invariant, actual_last_invariant);
    return !failure;
}

bool all_suites(const std::string& path) {
    bool result = true;
    for (const TestCase& test_case: read_suite(path)) {
        result = result && bool(run_yaml_test_case(test_case));
    }
    return result;
}

void foreach_suite(const std::string& path, std::function<void(const TestCase&)> f) {
    for (const TestCase& test_case: read_suite(path)) {
        f(test_case);
    }
}