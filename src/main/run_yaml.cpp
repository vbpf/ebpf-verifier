// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <iostream>
#include <vector>

#include <boost/functional/hash.hpp>

#include "CLI11.hpp"

#include "ebpf_verifier.hpp"
#include "ebpf_yaml.hpp"

int main(int argc, char** argv) {
    CLI::App app{"Run yaml test cases"};

    std::string filename;
    app.add_option("path", filename, "YAML file.")->required()->type_name("FILE");
    CLI11_PARSE(app, argc, argv);

    bool res = all_suites(filename);
    if (res)
        std::cout << "pass\n";
    else
        std::cout << "failed\n";
    return !res;
}
