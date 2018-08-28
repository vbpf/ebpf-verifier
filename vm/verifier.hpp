#pragma once

#include <string>
#include <vector>
#include <map>

#include "instructions.hpp"
#include "type_descriptors.hpp"

using std::string;
using std::map;
using std::vector;

bool abs_validate(vector<struct ebpf_inst> insts,
                  string domain_name, ebpf_prog_type prog_type);

map<string, string> domain_descriptions();

bool validate_simple(vector<ebpf_inst> instructions, string& errmsg);

// defaults are in verifier.cpp
struct global_options_t
{
    bool simplify;
    bool stats;
    bool check_raw_reachability;
    bool check_semantic_reachability;
    bool print_invariants;
    bool liveness;
};

extern global_options_t global_options;
