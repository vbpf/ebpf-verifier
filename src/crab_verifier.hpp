#pragma once

#include <string>
#include <vector>
#include <map>

#include "spec_type_descriptors.hpp"

#include "asm_cfg.hpp"

bool abs_validate(Cfg const& simple_cfg, std::string domain_name, program_info info);

std::map<std::string, std::string> domain_descriptions();

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
