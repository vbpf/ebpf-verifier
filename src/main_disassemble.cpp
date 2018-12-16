#include <iostream>
#include <fstream>
#include <vector>
#include <set>
#include <sys/stat.h>
#include <unistd.h>

#include "asm.hpp"
#include "spec_assertions.hpp"

using std::string;

int main(int argc, char **argv)
{
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " file [option...]\n";
        return 65;
    }
    auto [is, nbytes] = open_binary_file(argv[1]);
    auto prog = unmarshal(is, nbytes);
    std::set<string> flags(argv+2, argv+argc);
    return std::visit(overloaded {
        [](string errmsg) {
            std::cout << "Bad file: " << errmsg << "\n";
            return 1;
        },
        [&](auto prog) {
            if (flags.count("raw")) {
                print(prog);
            } else {
                Cfg cfg = Cfg::make(prog);
                if (flags.count("nondet")) {
                    cfg = cfg.to_nondet(flags.count("expand_locks"));
                }
                if (flags.count("explicit")) {
                    explicate_assertions(cfg);
                }
                if (flags.count("simplify")) {
                    cfg.simplify();
                }
                if (flags.count("dot"))
                    print_dot(cfg);
                else 
                    print(cfg, flags.count("nondet"));
            }
            std::cout << "\n";
            return 0;
        },
    }, prog);
}
