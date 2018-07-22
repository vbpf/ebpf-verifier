#pragma once

#include <string>
#include <vector>
#include <map>

#include "instructions.hpp"

using std::string;
using std::map;
using std::vector;

/*** Interface to the loader.
 true if valid; *errmsg will point to NULL
 false if invalid; *errmsg will point to a heap-allocated error message
*/
bool abs_validate(vector<struct ebpf_inst> insts,
                  string domain_name, enum ebpf_prog_type prog_type);

map<string, string> domain_descriptions();

#define STACK_SIZE 128

struct ebpf_inst;

bool validate_simple(vector<ebpf_inst> instructions, string& errmsg);
