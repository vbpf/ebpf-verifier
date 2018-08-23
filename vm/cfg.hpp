#ifndef ABS_CFG_CPP
#define ABS_CFG_CPP

#include <vector>
#include <string>

#include <boost/lexical_cast.hpp>
#include "type_descriptors.hpp"
#include "common.hpp"

inline auto label(int pc) { return std::to_string(pc); }

inline auto label(int pc, std::string target){  return label(pc) + ":" + target; }

inline auto label(int pc, int target) { return label(pc, std::to_string(target)); }

inline auto exit_label(int pc) { return label(pc, "exit"); }

inline auto entry_label() { return label(-1, "entry"); }

inline int first_num(const std::string& s)
{
    return boost::lexical_cast<int>(s.substr(0, s.find_first_of(':')));
}

inline int first_num(const basic_block_t& block)
{
    return first_num(block.label());
}

std::vector<std::string> sorted_labels(cfg_t& cfg);


inline basic_block_t& add_common_child(cfg_t& cfg, basic_block_t& block, std::vector<basic_block_label_t> labels, std::string suffix)
{
    basic_block_t& child = cfg.insert(block.label() + ":" + suffix);
    for (auto label : labels)
        cfg.get_node(label) >> child;
    return child;
}

inline basic_block_t& add_child(cfg_t& cfg, basic_block_t& block, std::string suffix)
{
    return add_common_child(cfg, block, {block.label()}, suffix);
}

bool check_raw_reachability(std::vector<ebpf_inst> insts);

void build_cfg(cfg_t& cfg, variable_factory_t& vfac, std::vector<ebpf_inst> insts, ebpf_prog_type prog_type);

#endif
