
#include <vector>
#include <string>

#include "ebpf.h"

#include "abs_common.hpp"

class cst_regs
{
    variable_factory_t vfac;	
    std::vector<var_t> regs;

public:
    cst_regs() {
        for (int i=0; i < 16; i++) {
            auto name = std::string("r") + std::to_string(i);
            regs.emplace_back(vfac[name], crab::INT_TYPE, 64);
        }
    }

    void jump(ebpf_inst inst, basic_block_t& block, bool taken);
    void exec(ebpf_inst inst, basic_block_t& block);
};

