#include <iostream>
#include <fstream>
#include <vector>

#include <boost/lexical_cast.hpp>

#include <crab/common/debug.hpp>

#include "crab_verifier.hpp"
#include "asm.hpp"

using std::string;
using std::vector;

static int usage(const char *name)
{
    std::cerr << "usage: " << name << " [FLAGS] BINARY [TYPE] [DOMAIN]\n";
    std::cerr << "\n";
    std::cerr << "verifies the eBPF code in BINARY using DOMAIN assuming program type TYPE\n";
    std::cerr << "\n";
    std::cerr << "DOMAIN is defaulted to sdbm-arr\n";
    std::cerr << "TYPE may be extracted from BINARY suffix\n";
    std::cerr << "\n";
    std::cerr << "flags: "
                 "--log=CRABLOG --verbose=N "
                 "--stats --simplify --no-liveness --semantic-reachability\n";
    std::cerr << "available domains:\n";
    for (auto const [name, desc] : domain_descriptions())
        std::cerr << "\t" << name << " - " << desc << "\n";
    return 64;
}

int main(int argc, char **argv)
{
    vector<string> args{argv+1, argv + argc};
    vector<string> posargs;
    program_info info;
    info.program_type = BpfProgType::UNSPEC;
    bool is_raw = true;
    string path;
    string domain = "sdbm-arr";
    string desired_section;
    bool info_only = false;
    bool print_asm = false;
    for (string arg : args) {
        if (arg.find("type=") == 0) {
            // type1 or type4
            info.program_type = (BpfProgType)std::stoi(arg.substr(5));
        } else if (arg.find("map") == 0) {
            // map64 map4096 [...]
            info.map_sizes.push_back(std::stoi(arg.substr(3)));
        } else if (arg.find("domain=") == 0) {
            domain = arg.substr(7);
        } else if (arg.find("elf=") == 0) {
            arg = arg.substr(4);
            is_raw = false;
            if (arg.find(":") != string::npos) {
                path = arg.substr(0, arg.find(":"));
                desired_section = arg.substr(arg.find(":") + 1);
            } else {
                path = arg;
            }
        } else if (arg.find("raw=") == 0) {
            is_raw = true;
            path = arg.substr(4);
            if (info.program_type == BpfProgType::UNSPEC) {
                info.program_type = (BpfProgType)boost::lexical_cast<int>(path.substr(path.find_last_of('.') + 1));
            }
        } else if (arg.find("--log=") == 0) {
            crab::CrabEnableLog(arg.substr(6));
        } else if (arg == "--disable-warnings") {
            crab::CrabEnableWarningMsg(false);
        } else if (arg == "--asm") {
            print_asm = true;
        } else if (arg == "-q") {
            crab::CrabEnableWarningMsg(false);
            global_options.print_invariants = false;
        } else if (arg == "-qq") {
            crab::CrabEnableWarningMsg(false);
            global_options.print_invariants = false;
            global_options.print_failures = false;
        } else if (arg == "--sanity") {
            crab::CrabEnableSanityChecks(true);
        } else if (arg.find("--verbose=") == 0) {
            if (arg[0] == '"') arg=arg.substr(1, arg.size()-1);
            crab::CrabEnableVerbosity(std::stoi(arg.substr(10)));
        } else if (arg == "--help" || arg == "-h") {
            return usage(argv[0]);
        } else if (arg == "--stats" || arg == "--stat") {
            global_options.stats = true;
        } else if (arg == "--simplify") {
            global_options.simplify = true;
        } else if (arg == "--semantic-reachability") {
            global_options.check_semantic_reachability = true;
        } else if (arg == "--no-print-invariants") {
            global_options.print_invariants = false;
        } else if (arg == "--no-liveness") {
            global_options.liveness = false;
        } else if (arg == "--info") {
            info_only = true;
        } else {
            posargs.push_back(arg);
        }
    }
    if (posargs.size() >= 1 || path.empty())
        return usage(argv[0]);

    if (domain_descriptions().count(domain) == 0) {
        std::cerr << "argument " << domain << " is not a valid domain\n";
        return usage(argv[0]);
    }
    auto progs = is_raw ? read_raw(path, info) : read_elf(path, desired_section);
    for (auto raw_prog : progs) {
        if (info_only) {
            std::cout << "section: " << raw_prog.section;
            std::cout << "  type: " << (int)raw_prog.info.program_type;
            std::cout << "  sizes: ";
            for (auto s : raw_prog.info.map_sizes) {
                std::cout << s << "; ";
            }
            std::cout << "\n";
        } else {
            auto prog_or_error = unmarshal(raw_prog);
            std::visit(overloaded {
                [domain, raw_prog, print_asm](auto prog) {
                    if (print_asm) {
                        print(prog);
                    }
                    Cfg nondet_cfg = Cfg::make(prog).to_nondet(true);
                    const auto [res, seconds] = abs_validate(nondet_cfg, domain, raw_prog.info);
                    std::cout << res << "," << seconds << ",";
                    std::cout << raw_prog.filename << ":" << raw_prog.section;
                    print_stats(nondet_cfg);
                },
                [](string errmsg) { 
                    std::cout << "trivial verification failure: " << errmsg << "\n";
                }
            }, prog_or_error);
        }
    }
    return 0;
}
