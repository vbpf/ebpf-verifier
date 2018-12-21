#include <iostream>
#include <fstream>
#include <vector>
#include <unistd.h>

#include "asm.hpp"
#include "spec_assertions.hpp"

using std::string;

int main(int argc, char **argv)
{
    if (argc > 4 || argc < 2) {
        std::cerr << "Usage: " << argv[0] << " file\n";
        return 65;
    }
    string mode = argc < 3 ? "raw" : argv[2];
    string subcommand = argc < 4 ? "" : argv[3];
    auto is = open_asm_file(argv[1]);
    InstructionSeq prog = parse_program(is);
    if (mode == "quiet") {
        return 0;
    }
    if (mode == "-o") {
        auto out = marshal(prog);
        write_binary_file(subcommand, (char*)out.data(), out.size() * sizeof(out[0]));
        return 0;
    } 
    if (mode == "raw") {
        print(prog);
    } else {
        Cfg cfg = Cfg::make(prog);
        if (mode == "nondet") {
            cfg = cfg.to_nondet(false);
        }
        if (subcommand == "explicit") {
            explicate_assertions(cfg, {32}); // FIX: this is an example
        }
        print(cfg, mode == "nondet");
    }
    std::cout << "\n";
    return 0;
}
