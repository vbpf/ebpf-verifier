#include <iostream>
#include <fstream>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>

#include "asm.hpp"
using std::string;

static auto readfile(string path)
{
    struct stat path_stat;
    stat(path.c_str(), &path_stat);
    if (!S_ISREG(path_stat.st_mode)) {
        std::cerr << "Cannot read from a directory: " << path << "\n";
        exit(65);
    }
    using std::ifstream;
    ifstream is(path, ifstream::ate | ifstream::binary);
    if (is.fail()) {
        std::cerr << "file " << path << " does not exist\n";
        exit(65);
    }
    size_t nbytes = is.tellg();
    is.seekg(0);
    return parse(is, nbytes);
}

int main(int argc, char **argv)
{
    if (argc > 3 || argc < 2) {
        std::cerr << "Usage: " << argv[0] << " file\n";
        return 65;
    }
    string mode = argc < 3 ? "raw" : argv[2];
    return std::visit(overloaded {
        [=](Program prog) {
            if (mode == "raw") {
                print(prog);
            } else {
                Cfg cfg = build_cfg(prog);
                if (mode == "cfg") {
                    print(cfg, false);
                } else if (mode == "nondet") {
                    print(to_nondet(cfg), true);
                }
            }
            std::cout << "\n";
            return 0; },
        [](string errmsg) { 
            std::cout << "Bad file: " << errmsg << "\n";
            return 1;
        }
    }, readfile(argv[1]));
}
