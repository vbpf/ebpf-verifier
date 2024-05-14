// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <iostream>
#include <vector>

#include <boost/algorithm/string.hpp>
#include <boost/functional/hash.hpp>

#include "CLI11.hpp"

#include "ebpf_verifier.hpp"
#ifdef _WIN32
#include "memsize_windows.hpp"
#else
#include "memsize_linux.hpp"
#endif
#include "linux_verifier.hpp"
#include "utils.hpp"

using std::string;
using std::vector;

static size_t hash(const raw_program& raw_prog) {
    char* start = (char*)raw_prog.prog.data();
    char* end = start + (raw_prog.prog.size() * sizeof(ebpf_inst));
    return boost::hash_range(start, end);
}

template <void (on_exit)()>
struct at_scope_exit
{
    at_scope_exit() = default;
    ~at_scope_exit() { on_exit(); }
};

static const std::map<std::string, bpf_conformance_groups_t> _conformance_groups = {
    {"atomic32", bpf_conformance_groups_t::atomic32},
    {"atomic64", bpf_conformance_groups_t::atomic64},
    {"base32", bpf_conformance_groups_t::base32},
    {"base64", bpf_conformance_groups_t::base64},
    {"callx", bpf_conformance_groups_t::callx},
    {"divmul32", bpf_conformance_groups_t::divmul32},
    {"divmul64", bpf_conformance_groups_t::divmul64},
    {"packet", bpf_conformance_groups_t::packet}};

static std::optional<bpf_conformance_groups_t> _get_conformance_group_by_name(std::string group) {
    if (!_conformance_groups.contains(group)) {
        return {};
    }
    return _conformance_groups.find(group)->second;
}

static std::string _get_conformance_group_names() {
    std::string result;
    for (const auto& entry : _conformance_groups) {
        if (!result.empty()) {
            result += ", ";
        }
        result += entry.first;
    }
    return result;
}

// Given a string containing comma-separated tokens, split them into a list of strings.
static std::vector<std::string> get_string_vector(std::string list) {
    std::vector<std::string> string_vector;
    if (!list.empty())
       boost::split(string_vector, list, boost::is_any_of(","));
    return string_vector;
}

static std::optional<raw_program> find_program(vector<raw_program>& raw_progs, std::string desired_program) {
    if (desired_program.empty() && raw_progs.size() != 1) {
        // Select the last program section.
        return raw_progs.back();
    }
    for (raw_program current_program : raw_progs) {
        if (current_program.function_name == desired_program) {
            return current_program;
        }
    }
    return {};
}

int main(int argc, char** argv) {
    // Always call ebpf_verifier_clear_thread_local_state on scope exit.
    at_scope_exit<ebpf_verifier_clear_thread_local_state> clear_thread_local_state;

    ebpf_verifier_options_t ebpf_verifier_options = ebpf_verifier_default_options;

    // Parse command line arguments:

    crab::CrabEnableWarningMsg(false);

    CLI::App app{"A new eBPF verifier"};

    std::string filename;
    app.add_option("path", filename, "Elf file to analyze")->required()->type_name("FILE");

    std::string desired_section;

    app.add_option("section", desired_section, "Section to analyze")->type_name("SECTION");

    std::string desired_program;

    app.add_option("program", desired_program, "Program to analyze")->type_name("PROGRAM");
    bool list = false;
    app.add_flag("-l", list, "List programs");

    std::string domain = "zoneCrab";
    std::set<string> doms{"stats", "linux", "zoneCrab", "cfg"};
    app.add_set("-d,--dom,--domain", domain, doms, "Abstract domain")->type_name("DOMAIN");

    app.add_flag("--termination", ebpf_verifier_options.check_termination, "Verify termination");

    app.add_flag("--assume-assert", ebpf_verifier_options.assume_assertions, "Assume assertions");

    bool verbose = false;
    app.add_flag("-i", ebpf_verifier_options.print_invariants, "Print invariants");
    app.add_flag("-f", ebpf_verifier_options.print_failures, "Print verifier's failure logs");
    app.add_flag("-s", ebpf_verifier_options.strict, "Apply additional checks that would cause runtime failures");
    app.add_flag("-v", verbose, "Print both invariants and failures");
    std::string include_groups;
    app.add_option("include_groups", include_groups,
                   "Include conformance groups (valid group names: " + _get_conformance_group_names() + ")");
    std::string exclude_groups;
    app.add_option("exclude_groups", exclude_groups,
                   "Exclude conformance groups (valid group names: " + _get_conformance_group_names() + ")");
    bool no_division_by_zero = false;
    app.add_flag("--no-division-by-zero", no_division_by_zero, "Do not allow division by zero");
    app.add_flag("--no-simplify", ebpf_verifier_options.no_simplify, "Do not simplify");
    app.add_flag("--line-info", ebpf_verifier_options.print_line_info, "Print line information");
    app.add_flag("--print-btf-types", ebpf_verifier_options.dump_btf_types_json, "Print BTF types");

    std::string asmfile;
    app.add_option("--asm", asmfile, "Print disassembly to FILE")->type_name("FILE");
    std::string dotfile;
    app.add_option("--dot", dotfile, "Export control-flow graph to dot FILE")->type_name("FILE");

    app.footer("You can use @headers as the path to instead just show the output field headers.\n");

    CLI11_PARSE(app, argc, argv);
    if (verbose)
        ebpf_verifier_options.print_invariants = ebpf_verifier_options.print_failures = true;
    ebpf_verifier_options.allow_division_by_zero = !no_division_by_zero;

    // Enable default conformance groups, which don't include callx or packet.
    ebpf_platform_t platform = g_ebpf_platform_linux;
    platform.supported_conformance_groups = bpf_conformance_groups_t::default_groups;
    for (auto group_name : get_string_vector(include_groups)) {
        if (auto group = _get_conformance_group_by_name(group_name)) {
            platform.supported_conformance_groups |= *group;
        } else {
            std::cerr << "Invalid group: " << group_name << std::endl;
            return 1;
        }
    }
    for (auto group_name : get_string_vector(exclude_groups)) {
        if (auto group = _get_conformance_group_by_name(group_name)) {
            platform.supported_conformance_groups &= ~(*group);
        } else {
            std::cerr << "Invalid group: " << group_name << std::endl;
            return 1;
        }
    }

    // Main program

    if (filename == "@headers") {
        if (domain == "stats") {
            std::cout << "hash";
            std::cout << ",instructions";
            for (const string& h : stats_headers()) {
                std::cout << "," << h;
            }
        } else {
            std::cout << domain << "?,";
            std::cout << domain << "_sec,";
            std::cout << domain << "_kb";
        }
        std::cout << "\n";
        return 0;
    }

#if !__linux__
    if (domain == "linux") {
        std::cerr << "error: linux domain is unsupported on this machine\n";
        return 64;
    }
#endif

    if (domain == "linux")
        ebpf_verifier_options.mock_map_fds = false;

    // Read a set of raw program sections from an ELF file.
    vector<raw_program> raw_progs;
    try {
        raw_progs = read_elf(filename, desired_section, &ebpf_verifier_options, &platform);
    } catch (std::runtime_error& e) {
        std::cerr << "error: " << e.what() << std::endl;
        return 1;
    }

    std::optional<raw_program> found_prog = find_program(raw_progs, desired_program);
    if (list || !found_prog) {
        if (!list) {
            std::cout << "please specify a program\n";
            std::cout << "available programs:\n";
        }
        if (!desired_section.empty() && raw_progs.empty()) {
            // We could not find the desired program, so get the full list
            // of possibilities.
            raw_progs = read_elf(filename, string(), &ebpf_verifier_options, &platform);
        }
        for (const raw_program& raw_prog : raw_progs) {
            std::cout << raw_prog.function_name << " ";
        }
        std::cout << "\n";
        return list ? 0 : 64;
    }
    raw_program raw_prog = *found_prog;

    // Convert the raw program section to a set of instructions.
    std::variant<InstructionSeq, std::string> prog_or_error = unmarshal(raw_prog);
    if (std::holds_alternative<string>(prog_or_error)) {
        std::cout << "unmarshaling error at " << std::get<string>(prog_or_error) << "\n";
        return 1;
    }

    auto& prog = std::get<InstructionSeq>(prog_or_error);
    if (!asmfile.empty()) {
        std::ofstream out{asmfile};
        print(prog, out, {});
        print_map_descriptors(global_program_info->map_descriptors, out);
    }

    if (domain == "zoneCrab") {
        ebpf_verifier_stats_t verifier_stats;
        const auto [res, seconds] = timed_execution([&] {
            return ebpf_verify_program(std::cout, prog, raw_prog.info, &ebpf_verifier_options, &verifier_stats);
        });
        if (res && ebpf_verifier_options.check_termination && (ebpf_verifier_options.print_failures || ebpf_verifier_options.print_invariants)) {
            std::cout << "Program terminates within " << verifier_stats.max_loop_count << " loop iterations\n";
        }
        std::cout << res << "," << seconds << "," << resident_set_size_kb() << "\n";
        return !res;
    } else if (domain == "linux") {
        // Pass the instruction sequence to the Linux kernel verifier.
        const auto [res, seconds] = bpf_verify_program(raw_prog.info.type, raw_prog.prog, &ebpf_verifier_options);
        std::cout << res << "," << seconds << "," << resident_set_size_kb() << "\n";
        return !res;
    } else if (domain == "stats") {
        // Convert the instruction sequence to a control-flow graph.
        cfg_t cfg = prepare_cfg(prog, raw_prog.info, !ebpf_verifier_options.no_simplify);

        // Just print eBPF program stats.
        auto stats = collect_stats(cfg);
        if (!dotfile.empty()) {
            print_dot(cfg, dotfile);
        }
        std::cout << std::hex << hash(raw_prog) << std::dec << "," << prog.size();
        for (const string& h : stats_headers()) {
            std::cout << "," << stats.at(h);
        }
        std::cout << "\n";
    } else if (domain == "cfg") {
        // Convert the instruction sequence to a control-flow graph.
        cfg_t cfg = prepare_cfg(prog, raw_prog.info, !ebpf_verifier_options.no_simplify);
        std::cout << cfg;
        std::cout << "\n";
    } else {
        assert(false);
    }

    return 0;
}
