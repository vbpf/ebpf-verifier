#pragma once

#include <string>
#include <vector>
#include <map>

#include "instructions.hpp"

using std::string;
using std::map;
using std::vector;

bool abs_validate(vector<struct ebpf_inst> insts,
                  string domain_name, enum ebpf_prog_type prog_type);

map<string, string> domain_descriptions();

#define STACK_SIZE 128

struct ebpf_inst;

bool validate_simple(vector<ebpf_inst> instructions, string& errmsg);

struct global_options_t
{
    bool simplify;
    bool stats;
    bool check_reachability;
};

extern global_options_t global_options;
