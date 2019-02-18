#include <iostream>
#include <vector>

#include <crab/common/debug.hpp>

#include <boost/container_hash/hash.hpp>

#include "CLI11.hpp"

#include "config.hpp"
#include "crab_verifier.hpp"
#include "asm.hpp"
#include "spec_assertions.hpp"
#include "ai.hpp"

using std::string;
using std::vector;

static size_t hash(const raw_program& raw_prog) {
    char* start = (char*)raw_prog.prog.data();
    char* end = start + (raw_prog.prog.size() * sizeof(ebpf_inst));
    return boost::hash_range(start, end);
}

int main(int argc, char **argv)
{
    crab::CrabEnableWarningMsg(false);

    CLI::App app{"a new eBPF verifier"};

    std::string filename;
    app.add_option("path", filename, "elf file to analyze")->required()->check(CLI::ExistingFile)->type_name("FILE");

    std::string desired_section;
    app.add_option("section", desired_section,"section to analyze")->type_name("SECTION");

    std::string domain="sdbm-arr";
    std::set<string> doms;
    for (auto const [name, desc] : domain_descriptions())
        doms.insert(name);
    app.add_set("-d,--dom,--domain", domain, doms, "abstract domain")->type_name("DOMAIN");

    app.add_flag("-v", global_options.print_invariants, "print invariants");
    
    std::string asmfile;
    app.add_option("--asm", asmfile, "print disassembly")->type_name("FILE");
    std::string dotfile;
    app.add_option("--dot", dotfile, "export cfg to dot file")->type_name("FILE");

    CLI11_PARSE(app, argc, argv);

    auto raw_progs = read_elf(filename, desired_section);
    if (raw_progs.size() != 1) {
        std::cerr << "please specify a section\n";
        std::cerr << "available sections:\n";
        for (raw_program raw_prog : raw_progs) {
            std::cout << "  " << raw_prog.section << "\t(" << raw_prog.prog.size() << " bytes)\n";
        }
        return 64;
    }
    auto raw_prog = raw_progs.back();
    auto prog_or_error = unmarshal(raw_prog);
    if (std::holds_alternative<string>(prog_or_error)) {
        std::cout << "trivial verification failure: " << std::get<string>(prog_or_error) << "\n";
        return 1;
    }
    auto& prog = std::get<InstructionSeq>(prog_or_error);
    Cfg cfg = Cfg::make(prog).to_nondet(true);
    cfg.simplify();
    const auto [res, seconds] = abs_validate(cfg, domain, raw_prog.info);
    auto stats = cfg.collect_stats();
    
    if (!dotfile.empty()) print_dot(cfg, dotfile);
    if (!asmfile.empty()) print(prog, asmfile);

    std::cout << res << "," << seconds << ",";
    std::cout << raw_prog.filename << ":" << raw_prog.section << ",";
    std::cout << std::hex << hash(raw_prog) << std::dec << ",";
    std::cout << stats.count << "," << stats.loads << "," << stats.stores << "," << stats.jumps << "," << stats.joins << "\n";
    return 0;
}
