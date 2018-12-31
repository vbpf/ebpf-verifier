#include <iostream>
#include <fstream>
#include <vector>
#include <set>
#include <sys/stat.h>
#include <unistd.h>

#include "asm.hpp"
#include "spec_assertions.hpp"
#include "ai.hpp"

using std::string;

int main(int argc, char **argv)
{
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " file [option...]\n";
        return 65;
    }
    std::vector<std::vector<std::string>> notes;
    auto prog = unmarshal(read_raw(argv[1], program_info{}).at(0), notes);

    int pc = 0;
    for (auto notelist : notes) {
        pc++;
        for (auto s : notelist) {
            std::cerr << "Note (" << pc << "): " << s << "\n";
        }
    }
    std::set<string> flags(argv+2, argv+argc);
    return std::visit(overloaded {
        [](string errmsg) {
            std::cout << "Bad file: " << errmsg << "\n";
            return 1;
        },
        [&](auto prog) {
            if (flags.empty()) {
                print(prog);
            } else {
                Cfg cfg = Cfg::make(prog);
                if (flags.count("nondet")) {
                    cfg = cfg.to_nondet(flags.count("expand_locks"));
                }
                if (flags.count("explicit")) {
                    explicate_assertions(cfg, {32}); // FIX: this is an example
                }
                if (flags.count("simplify")) {
                    cfg.simplify();
                }
                if (flags.count("rcp")) {
                    analyze_rcp(cfg, 1); // FIX: same
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
