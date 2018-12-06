#include <iostream>
#include <fstream>
#include <vector>
#include <sys/stat.h>
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
                if (mode == "nondet") {
                    cfg = cfg.to_nondet();
                }
                if (subcommand == "explicit") {
                    explicate_assertions(cfg);
                }
                print(cfg, mode == "nondet");
            }
            std::cout << "\n";
            return 0;
        },
    }, prog);
}
