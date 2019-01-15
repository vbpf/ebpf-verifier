#include <iostream>
#include <fstream>
#include <vector>

#include <boost/lexical_cast.hpp>

#include <crab/common/debug.hpp>

#include <boost/container_hash/hash.hpp>

#include "crab_verifier.hpp"
#include "asm.hpp"
#include "spec_assertions.hpp"
#include "ai.hpp"

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
    string outdir = "output";
    bool info_only = false;
    bool print_asm = false;
    bool list_only = false;
    bool nondet = false;
    bool expand_locks = false;
    bool explicit_assertions = false;
    bool rcp = false;
    bool crab = false;
    for (string arg : args) {
        if (arg.find("type=") == 0) {
            // type1 or type4
            info.program_type = (BpfProgType)std::stoi(arg.substr(5));
        } else if (arg.find("map") == 0) {
            // map64 map4096 [...]
            info.map_defs.emplace_back(map_def{.value_size=static_cast<unsigned int>(std::stoi(arg.substr(3)))});
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
        } else if (arg.find("-l") == 0) {
            list_only = true;
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
        } else if (arg.find("--out=") == 0) {
            outdir = arg.substr(6);
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
        } else if (arg == "nondet") {
            nondet = true;
        } else if (arg == "expand_locks") {
            expand_locks = true;
        } else if (arg == "explicit") {
            explicit_assertions = true;
        } else if (arg == "rcp") {
            nondet = true;
            explicit_assertions = true;
            rcp = true;
        } else if (arg == "crab") {
            nondet = true;
            expand_locks = true;
            crab = true;
        } else {
            posargs.push_back(arg);
        }
    }
    if (path.empty())
        return usage(argv[0]);

    if (domain_descriptions().count(domain) == 0) {
        std::cerr << "argument " << domain << " is not a valid domain\n";
        return usage(argv[0]);
    }
    auto progs = is_raw ? read_raw(path, info) : read_elf(path, desired_section);
    for (raw_program raw_prog : progs) {
        //std::cerr << raw_prog.filename << ":" << raw_prog.section << "\n";
        if (list_only) {
            continue;
        }
        if (info_only) {
            std::cout << "  type: " << (int)raw_prog.info.program_type;
            std::cout << "  sizes: ";
            for (auto s : raw_prog.info.map_defs) {
                std::cout << s.value_size << "; ";
            }
            std::cout << "\n";
        } else {
            string basename = raw_prog.filename.substr(raw_prog.filename.find_last_of('/') + 1);
            string outsubdir = outdir + "/" + basename + "/" + raw_prog.section + "/";
            (void)system((string() + "mkdir -p " + outsubdir).c_str());
            auto prog_or_error = unmarshal(raw_prog);
            if (std::holds_alternative<string>(prog_or_error)) {
                std::cout << "trivial verification failure: " << std::get<string>(prog_or_error) << "\n";
                return 1;
            }
            auto& prog = std::get<InstructionSeq>(prog_or_error);
            if (print_asm) {
                std::ofstream out{outsubdir + "raw.txt"};
                print(prog, out);
            } else {
                Cfg cfg = Cfg::make(prog);
                if (explicit_assertions) {
                    explicate_assertions(cfg, raw_prog.info);
                    if (global_options.print_invariants) {
                        std::ofstream out{outsubdir + "explicit.dot"};
                        print_dot(cfg, out);
                    }
                }
                if (nondet) {
                    cfg = cfg.to_nondet(expand_locks);
                    if (global_options.print_invariants) {
                        std::ofstream out{outsubdir + "nondet.dot"};
                        print_dot(cfg, out);
                    }
                }
                if (global_options.simplify) {
                    cfg.simplify();
                    if (global_options.print_invariants) {
                        std::ofstream out{outsubdir + "simplified.dot"};
                        print_dot(cfg, out);
                    }
                }
                if (rcp) {
                    analyze_rcp(cfg, raw_prog.info);
                }
                if (global_options.print_invariants) {
                    std::ofstream out{outsubdir + "rcp.dot"};
                    print_dot(cfg, out);
                }
                if (global_options.print_invariants) {
                    std::ofstream out{outsubdir + "rcp.txt"};
                    print(cfg, nondet,  out);
                }
                if (crab) {
                    const auto [res, seconds] = abs_validate(cfg, domain, raw_prog.info);
                    std::cout << res << "," << seconds << ",";
                    std::cout << raw_prog.filename << ":" << raw_prog.section << ",";
                    std::cout << std::hex << boost::hash_range((char*)raw_prog.prog.data(), (char*)raw_prog.prog.data()+(raw_prog.prog.size() * sizeof(ebpf_inst))) << std::dec << ",";
                    print_stats(cfg);
                }

                // std::cout << "section:" << raw_prog.section << "\n";
                // std::cout << "type: " << (int)raw_prog.info.program_type << "\n";
                // std::cout << "data: " << raw_prog.info.descriptor.data << "\n";
                // std::cout << "end: " << raw_prog.info.descriptor.end << "\n";
                // std::cout << "meta: " << raw_prog.info.descriptor.meta << "\n";
                // std::cout << "size: " << raw_prog.info.descriptor.size << "\n";
            }
        }
    }
    return 0;
}
