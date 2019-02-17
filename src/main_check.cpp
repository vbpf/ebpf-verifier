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

static int usage(string name)
{
    std::cerr << "usage: " << name << " [FLAGS] BINARY[:SECTION]\n";
    std::cerr << "\n";
    std::cerr << "check the eBPF code in BINARY (only SECTION if specified)\n";
    std::cerr << "\n";
    std::cerr << "The default domain is sdbm-arr\n";
    std::cerr << "\n";
    std::cerr << "flags: "
                 "--log=CRABLOG --verbose=N -v -vv --enable-warnings -l --asm "
                 "--explicit --rcp --print-invariants --expand-locks "
                 "--stats --no-simplify --no-liveness --semantic-reachability\n";
    std::cerr << "available domains:\n";
    for (auto const [name, desc] : domain_descriptions())
        std::cerr << "\t" << name << " - " << desc << "\n";
    return 64;
}

struct cmdline_args {
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
    string path;
};

cmdline_args parse_args(const vector<string> args) {
    vector<string> posargs;
    cmdline_args res;
    crab::CrabEnableWarningMsg(false);
    global_options.print_invariants = false;
    global_options.print_failures = false;

    res.nondet = true;
    res.expand_locks = true;
    res.crab = true;

    global_options.simplify = true;

    for (string arg : args) {
        if (arg.find("domain=") == 0) {
            res.domain = arg.substr(7);
        } else if (arg.find("-l") == 0) {
            res.list_only = true;
        } else if (arg == "--asm") {
            res.print_asm = true;
        } else if (arg.find("--log=") == 0) {
            crab::CrabEnableLog(arg.substr(6));
        } else if (arg == "--enable-warnings") {
            crab::CrabEnableWarningMsg(true);
        } else if (arg == "--print-invariants") {
            global_options.print_invariants = true;
        } else if (arg == "-v") {
            crab::CrabEnableWarningMsg(true);
            global_options.print_invariants = true;
        } else if (arg == "-vv") {
            crab::CrabEnableWarningMsg(true);
            global_options.print_invariants = true;
            global_options.print_failures = true;
        } else if (arg == "--sanity") {
            crab::CrabEnableSanityChecks(true);
        } else if (arg.find("--verbose=") == 0) {
            if (arg[0] == '"') arg=arg.substr(1, arg.size()-1);
            crab::CrabEnableVerbosity(std::stoi(arg.substr(10)));
        } else if (arg.find("--out=") == 0) {
            res.outdir = arg.substr(6);
        } else if (arg == "--help" || arg == "-h") {
            exit(usage(args[0]));
        } else if (arg == "--stats" || arg == "--stat") {
            global_options.stats = true;
        } else if (arg == "--no-simplify") {
            global_options.simplify = false;
        } else if (arg == "--semantic-reachability") {
            global_options.check_semantic_reachability = true;
        } else if (arg == "--no-liveness") {
            global_options.liveness = false;
        } else if (arg == "--info") {
            res.info_only = true;
        } else if (arg == "--nondet") {
            res.nondet = true;
        } else if (arg == "--expand_locks") {
            res.expand_locks = true;
        } else if (arg == "--explicit") {
            res.explicit_assertions = true;
        } else if (arg == "--rcp") {
            res.nondet = true;
            res.explicit_assertions = true;
            res.rcp = true;
        } else {
            posargs.push_back(arg);
        }
    }
    if (posargs.size() != 1)
        exit(usage(args[0]));

    string path = posargs.back();
    if (path.find(":") != string::npos) {
        res.desired_section = path.substr(path.find(":") + 1);
        res.path = path.substr(0, path.find(":"));
    } else {
        res.path = path;
    }

    if (domain_descriptions().count(res.domain) == 0) {
        std::cerr << "argument " << res.domain << " is not a valid domain\n";
        exit(usage(args[0]));
    }
    return res;
}

int main(int argc, char **argv)
{
    auto args = parse_args({argv+1, argv + argc});
    program_info info;
    info.program_type = BpfProgType::UNSPEC;

    auto progs = read_elf(args.path, args.desired_section);
    for (raw_program raw_prog : progs) {
        if (args.list_only) {
            std::cout << raw_prog.filename << ":" << raw_prog.section << "\n";
            continue;
        }
        if (args.info_only) {
            std::cout << "  type: " << (int)raw_prog.info.program_type;
            std::cout << "  sizes: ";
            for (auto s : raw_prog.info.map_defs) {
                std::cout << s.value_size << "; ";
            }
            std::cout << "\n";
        } else {
            string basename = raw_prog.filename.substr(raw_prog.filename.find_last_of('/') + 1);
            string outsubdir = args.outdir + "/" + basename + "/" + raw_prog.section + "/";
            (void)system((string() + "mkdir -p " + outsubdir).c_str());
            auto prog_or_error = unmarshal(raw_prog);
            if (std::holds_alternative<string>(prog_or_error)) {
                std::cout << "trivial verification failure: " << std::get<string>(prog_or_error) << "\n";
                return 1;
            }
            auto& prog = std::get<InstructionSeq>(prog_or_error);
            if (args.print_asm) {
                print(prog, std::cout);
            } else {
                Cfg cfg = Cfg::make(prog);
                if (args.explicit_assertions) {
                    explicate_assertions(cfg, raw_prog.info);
                    if (global_options.print_invariants) {
                        std::ofstream out{outsubdir + "explicit.dot"};
                        print_dot(cfg, out);
                    }
                }
                if (args.nondet) {
                    cfg = cfg.to_nondet(args.expand_locks);
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
                if (args.rcp) {
                    analyze_rcp(cfg, raw_prog.info);
                }
                if (global_options.print_invariants) {
                    std::ofstream out{outsubdir + "rcp.dot"};
                    print_dot(cfg, out);
                }
                if (global_options.print_invariants) {
                    std::ofstream out{outsubdir + "rcp.txt"};
                    print(cfg, args.nondet,  out);
                }
                if (args.crab) {
                    const auto [res, seconds] = abs_validate(cfg, args.domain, raw_prog.info);
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
