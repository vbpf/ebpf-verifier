#include <iostream>
#include <vector>

#include "crab/debug.hpp"

#include <boost/functional/hash.hpp>

#include "CLI11.hpp"

#include "ai.hpp"
#include "asm.hpp"
#include "config.hpp"
#include "crab_verifier.hpp"
#include "memsize.hpp"
#include "spec_assertions.hpp"

#include "linux_verifier.hpp"

using std::string;
using std::vector;

static size_t hash(const raw_program& raw_prog) {
    char* start = (char*)raw_prog.prog.data();
    char* end = start + (raw_prog.prog.size() * sizeof(ebpf_inst));
    return boost::hash_range(start, end);
}

int main(int argc, char** argv) {
    // Parse command line arguments:

    crab::CrabEnableWarningMsg(false);

    CLI::App app{"A new eBPF verifier"};

    std::string filename;
    app.add_option("path", filename, "Elf file to analyze")->required()->type_name("FILE");

    std::string desired_section;

    app.add_option("section", desired_section, "Section to analyze")->type_name("SECTION");
    bool list = false;
    app.add_flag("-l", list, "List sections");

    std::string domain = "zoneCrab";
    std::set<string> doms{"stats", "linux", "rcp", "zoneCrab"};
    app.add_set("-d,--dom,--domain", domain, doms, "Abstract domain")->type_name("DOMAIN");

    bool verbose = false;
    app.add_flag("-i", global_options.print_invariants, "Print invariants");
    app.add_flag("-f", global_options.print_failures, "Print verifier's failure logs");
    app.add_flag("-v", verbose, "Print both invariants and failures");

    std::string asmfile;
    app.add_option("--asm", asmfile, "Print disassembly to FILE")->type_name("FILE");
    std::string dotfile;
    app.add_option("--dot", dotfile, "Export cfg to dot FILE")->type_name("FILE");

    CLI11_PARSE(app, argc, argv);
    if (verbose)
        global_options.print_invariants = global_options.print_failures = true;

    // Main program

    if (filename == "@headers") {
        if (domain == "stats") {
            std::cout << "hash";
            std::cout << ",instructions";
            for (string h : Cfg::stats_headers()) {
                std::cout << "," << h;
            }
        } else {
            std::cout << domain << "?,";
            std::cout << domain << "_sec,";
            std::cout << domain << "_kb";
        }
        return 0;
    }

    auto create_map = domain == "linux" ? create_map_linux : domain == "rcp" ? create_map_rcp : create_map_crab;
    auto raw_progs = read_elf(filename, desired_section, create_map);

    if (list || raw_progs.size() != 1) {
        if (!list) {
            std::cout << "please specify a section\n";
            std::cout << "available sections:\n";
        }
        for (raw_program raw_prog : raw_progs) {
            std::cout << raw_prog.section << " ";
        }
        std::cout << "\n";
        return list ? 0 : 64;
    }
    raw_program raw_prog = raw_progs.back();

    auto prog_or_error = unmarshal(raw_prog);
    if (std::holds_alternative<string>(prog_or_error)) {
        std::cout << "trivial verification failure: " << std::get<string>(prog_or_error) << "\n";
        return 1;
    }

    auto& prog = std::get<InstructionSeq>(prog_or_error);
    if (!asmfile.empty())
        print(prog, asmfile);

    int instruction_count = prog.size();

    Cfg cfg = Cfg::make(prog);
    cfg = cfg.to_nondet(false);
    if (global_options.simplify) {
        cfg.simplify();
    }
    auto stats = cfg.collect_stats();
    if (!dotfile.empty())
        print_dot(cfg, dotfile);

    if (domain == "stats") {
        std::cout << std::hex << hash(raw_prog) << std::dec << "," << instruction_count;
        for (string h : Cfg::stats_headers()) {
            std::cout << "," << stats.at(h);
        }
        std::cout << "\n";
    } else if (domain == "rcp") {
        analyze_rcp(cfg, raw_prog.info);
    } else {
        const auto [res, seconds] = (domain == "linux") ? bpf_verify_program(raw_prog.info.program_type, raw_prog.prog)
                                                        : abs_validate(cfg, raw_prog.info);
        std::cout << res << "," << seconds << "," << resident_set_size_kb() << "\n";
        return !res;
    }
    return 0;
}
