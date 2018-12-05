#pragma once

#include <string>
#include <vector>
#include <map>

#include "type_descriptors.hpp"
#include "asm.hpp"

using std::string;
using std::map;
using std::vector;

bool abs_validate(Cfg const& simple_cfg, string domain_name, ebpf_prog_type prog_type);

map<string, string> domain_descriptions();

// defaults are in verifier.cpp
struct global_options_t
{
    bool simplify;
    bool stats;
    bool check_semantic_reachability;
    bool print_invariants;
    bool liveness;
};

extern global_options_t global_options;
