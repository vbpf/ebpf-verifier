#include <iostream>
#include <fstream>
#include <vector>

#include <crab/common/debug.hpp>

#include "verifier.hpp"

static vector<ebpf_inst> readfile(string path);


static int usage(const char *name)
{
    std::cerr << "usage: " << name << " [--log=CRABLOG] [--verbose=N] [--stats] [--simplify] DOMAIN BINARY TYPE\n";
    std::cerr << "\nverifies the eBPF code in BINARY using DOMAIN assuming program type TYPE\n";
    std::cerr << "available domains:\n";
    map<string, string> domains = domain_descriptions();
    for (auto const [name, desc] : domains)
        std::cerr << "\t" << name << " - " << desc << "\n";
    return 64;
}


int run(string domain_name, string code_filename, ebpf_prog_type prog_type)
{
    std::vector<ebpf_inst> code = readfile(code_filename);

    string errmsg;
    if (!validate_simple(code, errmsg)) {
        std::cout << "trivial verification failure: " << errmsg << "\n";
        return 1;
    }
    if (!abs_validate(code, domain_name, prog_type)) {
        std::cout << "verification failed\n";
        return 1;
    }
    return 0;
}


int main(int argc, char **argv)
{
    vector<string> args{argv+1, argv + argc};
    vector<string> posargs;
    for (string arg : args) {
        if (arg.find("--log=") == 0) {
            crab::CrabEnableLog(arg.substr(6));
        } else if (arg.find("--verbose=") == 0) {
            if (arg[0] == '"') arg=arg.substr(1, arg.size()-1);
            crab::CrabEnableVerbosity(std::stoi(arg.substr(10)));
        } else if (arg == "--help" || arg == "-h") {
	    return usage(argv[0]);
        } else if (arg == "--stats" || arg == "--stat") {
            global_options::stats = true;
        } else if (arg == "--simplify") {
            global_options::simplify = true;
        } else {
            posargs.push_back(arg);
        }
    }
    if (posargs.size() != 3)
        return usage(argv[0]);

    string domain = posargs[0];
    if (domain_descriptions().count(domain) == 0) {
        std::cerr << "argument " << domain << " is not a valid domain\n";
        return usage(argv[0]);
    }

    return run(posargs[0], posargs[1], (ebpf_prog_type)std::stoi(posargs[2]));
}


static vector<ebpf_inst> readfile(string path)
{
    using std::ifstream;
    ifstream is(path, ifstream::ate | ifstream::binary);
    size_t code_len = is.tellg();
    if (code_len % sizeof(ebpf_inst) != 0) {
        std::cerr << "file size must be a multiple of " << sizeof(ebpf_inst) << "\n";
        exit(65);
    }
    vector<ebpf_inst> code(code_len / sizeof(ebpf_inst));
    is.seekg(0);
    is.read((char*)code.data(), code_len);
    return code;
}
