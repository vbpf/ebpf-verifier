#pragma once

#include <map>
#include <vector>

#include "asm_syntax.hpp"
#include "crab/cfg.hpp"

using BasicBlock = crab::basic_block<Instruction>;
using Cfg = crab::cfg<Instruction>;
Cfg instruction_seq_to_cfg(const InstructionSeq&);
Cfg to_nondet(const Cfg&, bool expand_locks);
std::vector<std::string> stats_headers();
std::map<std::string, int> collect_stats(const Cfg&);
