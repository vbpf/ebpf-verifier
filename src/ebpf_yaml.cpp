// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <algorithm>
#include <iostream>
#include <set>
#include <variant>

#include <boost/algorithm/string.hpp>

#include <yaml-cpp/yaml.h>

#include "asm_parse.hpp"
#include "asm_ostream.hpp"
#include "ebpf_verifier.hpp"
#include "ebpf_yaml.hpp"
#include "string_constraints.hpp"

using std::vector;
using std::string;

static EbpfProgramType ebpf_get_program_type(const string& section, const string& path) {
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

static void ebpf_parse_maps_section(vector<EbpfMapDescriptor>& map_descriptors, const char* data, size_t map_record_size, int map_count,
                                    const struct ebpf_platform_t* platform, ebpf_verifier_options_t options) {
}

static EbpfMapDescriptor test_map_descriptor = {
    .original_fd=0,
    .type=0,
    .key_size=sizeof(uint32_t),
    .value_size=sizeof(uint32_t),
    .max_entries=4,
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

static EbpfProgramType make_program_type(const string& name, ebpf_context_descriptor_t* context_descriptor) {
    return EbpfProgramType{
        .name=name,
        .context_descriptor=context_descriptor,
        .platform_specific_data=0,
        .section_prefixes={},
        .is_privileged=false
    };
}

static std::set<string> vector_to_set(const vector<string>& s) {
    std::set<string> res;
    for (const auto& item : s)
        res.insert(item);
    return res;
}

std::set<string> operator-(const std::set<string>& a, const std::set<string>& b) {
    std::set<string> res;
    std::set_difference(a.begin(), a.end(), b.begin(), b.end(), std::inserter(res, res.begin()));
    return res;
}


static string_invariant read_invariant(const vector<string>& raw_invariant) {
    std::set<string> res = vector_to_set(raw_invariant);
    if (res == std::set<string>{"_|_"})
        return string_invariant{};
    return string_invariant{res};
}

struct RawTestCase {
    string test_case;
    std::set<string> options;
    vector<string> pre;
    vector<std::tuple<string, vector<string>>> raw_blocks;
    vector<string> post;
    std::set<string> messages;
};

static vector<string> parse_block(const YAML::Node& block_node) {
    vector<string> block;
    std::istringstream is{block_node.as<string>()};
    string line;
    while (std::getline(is, line))
        block.emplace_back(line);
    return block;
}

static auto parse_code(const YAML::Node& code_node) {
    vector<std::tuple<string, vector<string>>> res;
    for (const auto& item : code_node) {
        res.emplace_back(item.first.as<string>(), parse_block(item.second));
    }
    return res;
}

static std::set<string> as_set_empty_default(const YAML::Node& optional_node) {
    if (!optional_node.IsDefined() || optional_node.IsNull())
        return {};
    return vector_to_set(optional_node.as<vector<string>>());
}

static RawTestCase parse_case(const YAML::Node& case_node) {
    return RawTestCase {
        .test_case = case_node["test-case"].as<string>(),
        .options = as_set_empty_default(case_node["options"]),
        .pre = case_node["pre"].as<vector<string>>(),
        .raw_blocks = parse_code(case_node["code"]),
        .post = case_node["post"].as<vector<string>>(),
        .messages = as_set_empty_default(case_node["messages"]),
    };
}

static InstructionSeq raw_cfg_to_instruction_seq(const vector<std::tuple<string, vector<string>>>& raw_blocks) {
    std::map<string, crab::label_t> label_name_to_label;

    int label_index = 0;
    for (const auto& [label_name, raw_block] : raw_blocks) {
        label_name_to_label.emplace(label_name, label_index);
        // don't count large instructions as 2
        label_index += (int)raw_block.size();
    }

    InstructionSeq res;
    label_index = 0;
    for (const auto& [label_name, raw_block] : raw_blocks) {
        for (const string& line : raw_block) {
            try {
                const Instruction& ins = parse_instruction(line, label_name_to_label);
                if (std::holds_alternative<Undefined>(ins))
                    std::cout << "text:" << line << "; ins: " << ins << "\n";
                res.emplace_back(label_index, ins, std::optional<btf_line_info_t>());
            } catch (const std::exception& e) {
                std::cout << "text:" << line << "; error: " << e.what() << "\n";
                res.emplace_back(label_index, Undefined{0}, std::optional<btf_line_info_t>());
            }
            label_index++;
        }
    }
    return res;
}

static ebpf_verifier_options_t raw_options_to_options(const std::set<string>& raw_options) {
    ebpf_verifier_options_t options = ebpf_verifier_default_options;

    // All YAML tests use no_simplify and !setup_constraints.
    options.no_simplify = true;
    options.setup_constraints = false;

    for (const string& name : raw_options) {
        if (name == "!allow_division_by_zero") {
            options.allow_division_by_zero = false;
        } else if (name == "termination") {
            options.check_termination = true;
        } else if (name == "strict") {
            options.strict = true;
        } else {
            throw std::runtime_error("Unknown option: " + name);
        }
    }
    return options;
}

static TestCase read_case(const RawTestCase& raw_case) {
    return TestCase{
        .name = raw_case.test_case,
        .options = raw_options_to_options(raw_case.options),
        .assumed_pre_invariant = read_invariant(raw_case.pre),
        .instruction_seq = raw_cfg_to_instruction_seq(raw_case.raw_blocks),
        .expected_post_invariant = read_invariant(raw_case.post),
        .expected_messages = raw_case.messages
    };
}

static vector<TestCase> read_suite(const string& path) {
    std::ifstream f{path};
    vector<TestCase> res;
    for (const YAML::Node& config : YAML::LoadAll(f)) {
        res.push_back(read_case(parse_case(config)));
    }
    return res;
}

static std::set<string> extract_messages(const string& str) {
    vector<string> output;
    boost::split(output, str, boost::is_any_of("\n"));

    std::set<string> actual_messages;
    for (auto& item: output) {
        boost::trim(item);
        if (!item.empty())
            actual_messages.insert(item);
    }
    return actual_messages;
}

template<typename T>
static Diff<T> make_diff(const T& actual, const T& expected) {
    return Diff<T> {
        .unexpected = actual - expected,
        .unseen = expected - actual,
    };
}

std::optional<Failure> run_yaml_test_case(const TestCase& _test_case, bool debug) {
    TestCase test_case = _test_case;
    if (debug) {
        test_case.options.print_failures = true;
        test_case.options.print_invariants = true;
        test_case.options.no_simplify = true;
    }

    ebpf_context_descriptor_t context_descriptor{64, 0, 8, -1};
    EbpfProgramType program_type = make_program_type(test_case.name, &context_descriptor);

    program_info info{&g_platform_test, {}, program_type};

    std::ostringstream ss;
    const auto& [actual_last_invariant, result] = ebpf_analyze_program_for_test(
        ss, test_case.instruction_seq,
        test_case.assumed_pre_invariant,
        info, test_case.options);
    std::set<string> actual_messages = extract_messages(ss.str());

    if (actual_last_invariant == test_case.expected_post_invariant && actual_messages == test_case.expected_messages)
        return {};
    return Failure{
        .invariant = make_diff(actual_last_invariant, test_case.expected_post_invariant),
        .messages = make_diff(actual_messages, test_case.expected_messages)
    };
}

template <typename T>
static vector<T> vector_of(const std::vector<uint8_t>& bytes) {
    auto data = bytes.data();
    auto size = bytes.size();
    if ((size % sizeof(T) != 0) || size > UINT32_MAX || !data) {
        throw std::runtime_error("Invalid argument to vector_of");
    }
    return {(T*)data, (T*)(data + size)};
}

template <typename TS>
void add_stack_variable(std::set<std::string>& more, int& offset, const std::vector<uint8_t>& memory_bytes) {
    typedef typename std::make_unsigned<TS>::type TU;
    TS svalue;
    TU uvalue;
    memcpy(&svalue, memory_bytes.data() + offset + memory_bytes.size() - EBPF_STACK_SIZE, sizeof(TS));
    memcpy(&uvalue, memory_bytes.data() + offset + memory_bytes.size() - EBPF_STACK_SIZE, sizeof(TU));
    more.insert("s[" + std::to_string(offset) + "..." + std::to_string(offset + sizeof(TS) - 1) +
                "].svalue" + "=" + std::to_string(svalue));
    more.insert("s[" + std::to_string(offset) + "..." + std::to_string(offset + sizeof(TU) - 1) +
                "].uvalue" + "=" + std::to_string(uvalue));
    offset += sizeof(TS);
}

string_invariant stack_contents_invariant(const std::vector<uint8_t>& memory_bytes) {
    std::set<std::string> more = {"r1.type=stack",
                                  "r1.stack_offset=" + std::to_string(EBPF_STACK_SIZE - memory_bytes.size()),
                                  "r1.stack_numeric_size=" + std::to_string(memory_bytes.size()),
                                  "r10.type=stack",
                                  "r10.stack_offset=" + std::to_string(EBPF_STACK_SIZE),
                                  "s[" + std::to_string(EBPF_STACK_SIZE - memory_bytes.size()) + "..." +
                                      std::to_string(EBPF_STACK_SIZE - 1) + "].type=number"};

    int offset = EBPF_STACK_SIZE - (int)memory_bytes.size();
    if (offset % 2 != 0) {
        add_stack_variable<int8_t>(more, offset, memory_bytes);
    }
    if (offset % 4 != 0) {
        add_stack_variable<int16_t>(more, offset, memory_bytes);
    }
    if (offset % 8 != 0) {
        add_stack_variable<int32_t>(more, offset, memory_bytes);
    }
    while (offset < EBPF_STACK_SIZE) {
        add_stack_variable<int64_t>(more, offset, memory_bytes);
    }

    return string_invariant(more);
}

ConformanceTestResult run_conformance_test_case(const std::vector<uint8_t>& memory_bytes,
                                                const std::vector<uint8_t>& program_bytes, bool debug) {
    ebpf_context_descriptor_t context_descriptor{64, -1, -1, -1};
    EbpfProgramType program_type = make_program_type("conformance_check", &context_descriptor);

    program_info info{&g_platform_test, {}, program_type};

    auto insts = vector_of<ebpf_inst>(program_bytes);
    string_invariant pre_invariant = string_invariant::top();

    if (!memory_bytes.empty()) {
        if (memory_bytes.size() > EBPF_STACK_SIZE) {
            std::cerr << "memory size overflow\n";
            return {};
        }
        pre_invariant = pre_invariant + stack_contents_invariant(memory_bytes);
    }
    raw_program raw_prog{.prog = insts};
    raw_prog.info.platform = &g_ebpf_platform_linux;

    // Convert the raw program section to a set of instructions.
    std::variant<InstructionSeq, std::string> prog_or_error = unmarshal(raw_prog);
    if (std::holds_alternative<string>(prog_or_error)) {
        std::cerr << "unmarshaling error at " << std::get<string>(prog_or_error) << "\n";
        return {};
    }

    auto& prog = std::get<InstructionSeq>(prog_or_error);

    ebpf_verifier_options_t options = ebpf_verifier_default_options;
    if (debug) {
        print(prog, std::cout, {});
        options.print_failures = true;
        options.print_invariants = true;
        options.no_simplify = true;
    }

    try {
        std::ostringstream null_stream;
        const auto& [actual_last_invariant, result] =
            ebpf_analyze_program_for_test(null_stream, prog, pre_invariant, info, options);

        for (const std::string& invariant : actual_last_invariant.value()) {
            if (invariant.rfind("r0.svalue=", 0) == 0) {
                crab::number_t lb, ub;
                if (invariant[10] == '[') {
                    lb = std::stoll(invariant.substr(11));
                    ub = std::stoll(invariant.substr(invariant.find(",", 11) + 1));
                } else {
                    lb = ub = std::stoll(invariant.substr(10));
                }
                return {result, crab::interval_t(lb, ub)};
            }
        }
        return {result, crab::interval_t::top()};
    } catch (const std::exception&) {
        // Catch exceptions thrown in ebpf_domain.cpp.
        return {};
    }
}

void print_failure(const Failure& failure, std::ostream& out) {
    constexpr auto INDENT = "  ";
    if (!failure.invariant.unexpected.empty()) {
        std::cout << "Unexpected properties:\n" << INDENT << failure.invariant.unexpected << "\n";
    } else {
        std::cout << "Unexpected properties: None\n";
    }
    if (!failure.invariant.unseen.empty()) {
        std::cout << "Unseen properties:\n" << INDENT << failure.invariant.unseen << "\n";
    } else {
        std::cout << "Unseen properties: None\n";
    }

    if (!failure.messages.unexpected.empty()) {
        std::cout << "Unexpected messages:\n";
        for (const auto& item : failure.messages.unexpected) {
            std::cout << INDENT << item << "\n";
        }
    } else {
        std::cout << "Unexpected messages: None\n";
    }

    if (!failure.messages.unseen.empty()) {
        std::cout << "Unseen messages:\n";
        for (const auto& item : failure.messages.unseen) {
            std::cout << INDENT << item << "\n";
        }
    } else {
        std::cout << "Unseen messages: None\n";
    }
}

bool all_suites(const string& path) {
    bool result = true;
    for (const TestCase& test_case: read_suite(path)) {
        result = result && bool(run_yaml_test_case(test_case));
    }
    return result;
}

void foreach_suite(const string& path, const std::function<void(const TestCase&)>& f) {
    for (const TestCase& test_case: read_suite(path)) {
        f(test_case);
    }
}
