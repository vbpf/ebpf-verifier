#include <fstream>
#include <iostream>
#include <string>
#include <sys/stat.h>

#include "asm_files.hpp"

std::tuple<std::ifstream, size_t> open_binary_file(std::string path)
{
    using std::ifstream;
    ifstream is(path, ifstream::ate | ifstream::binary);
    if (is.fail()) {
        std::cerr << "file " << path << " does not exist\n";
        exit(65);
    }
    size_t nbytes = is.tellg();
    is.seekg(0);
    return std::make_tuple(std::move(is), nbytes);
}

void write_binary_file(std::string path, const char* data, size_t size) {
    using std::ofstream;
    ofstream os(path, ofstream::binary);
    if (os.fail()) {
        std::cerr << "file " << path << " does not exist\n";
        exit(65);
    }
    os.write(data, size);
}

std::ifstream open_asm_file(std::string path)
{
    struct stat path_stat;
    stat(path.c_str(), &path_stat);
    if (!S_ISREG(path_stat.st_mode)) {
        std::cerr << "Cannot read from a directory: " << path << "\n";
        exit(65);
    }
    std::ifstream is(path);
    if (is.fail()) {
        std::cerr << "file " << path << " does not exist\n";
        exit(65);
    }
    return is;
}
