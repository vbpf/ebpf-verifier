#include <iostream>
#include <fstream>
#include <vector>

#include "verifier.hpp"

static vector<ebpf_inst> readfile(string path);


static int usage(const char *name)
{
    std::cerr << "usage: " << name << " TYPE DOMAIN BINARY\n";
    std::cerr << "\nverifies the eBPF code in BINARY using DOMAIN assuming program type TYPE\n";
    std::cerr << "available domains:\n";
    map<string, string> domains = domain_descriptions();
    for (auto const [name, desc] : domains)
        std::cerr << "\t" << name << " - " << desc << "\n";
    return 64;
}


int run(ebpf_prog_type prog_type, string domain_name, string code_filename)
{
    std::vector<ebpf_inst> code = readfile(code_filename);

    char *errmsg;
    if (!validate_simple(code.data(), code.size(), &errmsg)) {
        std::cout << "trivial verification failure: " << errmsg << "\n";
        free(errmsg);
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
    if (argc < 4)
        return usage(argv[0]);

    if (domain_descriptions().count(argv[2]) == 0) {
        std::cerr << "argument " << argv[2] << " is not a valid domain\n";
        return usage(argv[0]);
    }
    return run((ebpf_prog_type)atoi(argv[1]), argv[2], argv[3]);
}


static vector<ebpf_inst> readfile(string path)
{
    using std::ifstream;
    ifstream is(path, ifstream::ate | ifstream::binary);
    size_t code_len = is.tellg();
    if (code_len % sizeof(ebpf_inst) != 0) {
        fprintf(stderr, "file size must be a multiple of 8\n");
        exit(65);
    }
    vector<ebpf_inst> code(code_len / sizeof(ebpf_inst));
    is.seekg(0);
    is.read((char*)code.data(), code_len);
    return code;
}
