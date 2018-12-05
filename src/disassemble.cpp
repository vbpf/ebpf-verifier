#include <iostream>
#include <fstream>
#include <vector>
#include <sys/stat.h>
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
    auto [is, nbytes] = open_binary_file(argv[1]);
    auto prog = unmarshal(is, nbytes);
    return std::visit(overloaded {
        [](string errmsg) {
            std::cout << "Bad file: " << errmsg << "\n";
            return 1;
        },
        [=](auto prog) {
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
        },
    }, prog);
}
