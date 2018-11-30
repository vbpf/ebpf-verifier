#include <iostream>
#include <fstream>
#include <vector>

#include "asm.hpp"
using std::string;

static auto readfile(string path)
{
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
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " file\n";
        return 65;
    }
    return std::visit(overloaded {
        [](Program prog) { print(prog); return 0; },
        [](string errmsg) { 
            std::cout << "Bad file: " << errmsg << "\n";
            return 1;
        }
    }, readfile(argv[1]));
}
