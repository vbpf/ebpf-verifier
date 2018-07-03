#ifndef ABS_CST_REGS_CPP
#define ABS_CST_REGS_CPP

#include <vector>
#include <string>

#include "ebpf.h"

#include "abs_common.hpp"

using crab::cfg_impl::variable_factory_t;
using ikos::z_number;

using var_t     = ikos::variable<z_number, varname_t>;
using lin_cst_t = ikos::linear_constraint<z_number, varname_t>;

class cst_regs
{
    variable_factory_t vfac;	
    std::vector<var_t> regs;

public:
    cst_regs();

    void jump(ebpf_inst inst, basic_block_t& block, bool taken);
    void exec(ebpf_inst inst, basic_block_t& block);
};
#endif
