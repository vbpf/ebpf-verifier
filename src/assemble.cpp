#include <iostream>
#include <fstream>
#include <vector>
#include <unistd.h>

#include "asm.hpp"
using std::string;

int main(int argc, char **argv)
{
    if (argc > 3 || argc < 2) {
        std::cerr << "Usage: " << argv[0] << " file\n";
        return 65;
    }
    string mode = argc < 3 ? "raw" : argv[2];
    auto is = open_asm_file(argv[1]);
    InstructionSeq prog = parse_program(is);
    if (mode == "quiet") {
        return 0;
    }
    if (mode == "raw") {
        print(prog);
    } else {
        Cfg cfg = Cfg::make(prog);
        if (mode == "cfg") {
            print(cfg, false);
        } else if (mode == "nondet") {
            print(cfg.to_nondet(), true);
        }
    }
    std::cout << "\n";
    return 0;
}
