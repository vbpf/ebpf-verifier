#ifndef ABS_CFG_CPP
#define ABS_CFG_CPP

#include <vector>

#include "abs_common.hpp"

inline auto label(uint16_t pc)
{
    return std::to_string(pc);
}

inline auto label(uint16_t pc, uint16_t target)
{
    return std::to_string(pc) + "-" + std::to_string(target);
}

void build_cfg(cfg_t& cfg, std::vector<ebpf_inst> insts);

#endif
