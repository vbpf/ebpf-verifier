#pragma once
#include <boost/lexical_cast.hpp>

#include "spec_type_descriptors.hpp"

#include "asm_syntax.hpp"
#include "asm_cfg.hpp"

#include "crab_common.hpp"

static auto label(int pc) { return std::to_string(pc); }
static auto label(int pc, Label target){  return label(pc) + ":" + target; }
static auto label(int pc, int target) { return label(pc, std::to_string(target)); }
static auto exit_label(Label label) { return label + ":exit"; }
inline auto entry_label() { return label(-1, "entry"); }

inline int first_num(const Label& s)
{
    return boost::lexical_cast<int>(s.substr(0, s.find_first_of(':')));
}

void build_crab_cfg(cfg_t& cfg, variable_factory_t& vfac, Cfg const& simple_cfg, ebpf_prog_type prog_type, std::vector<int> map_sizes);
