#ifndef ABS_CST_REGS_CPP
#define ABS_CST_REGS_CPP

#include <vector>
#include <string>
#include <memory>

#include "ebpf.h"

#include "abs_common.hpp"

using crab::cfg_impl::variable_factory_t;
using ikos::z_number;

using var_t     = ikos::variable<z_number, varname_t>;
using lin_cst_t = ikos::linear_constraint<z_number, varname_t>;

constexpr int STACK_SIZE=512;

// hand-crafted mix of absolute values and offsets 
class constraints final
{

    struct dom_t {
        var_t value;
        var_t offset;
        // TODO: region
        dom_t(variable_factory_t& vfac, int i) :
            value{vfac[std::string("r") + std::to_string(i)], crab::INT_TYPE, 64}, 
            offset{vfac[std::string("off") + std::to_string(i)], crab::INT_TYPE, 64}
        { }
    };

    variable_factory_t vfac;	
    std::vector<dom_t> regs;
    var_t stack{vfac["stack"], crab::ARR_INT_TYPE, 64};
    var_t ctx{vfac["ctx"], crab::ARR_INT_TYPE, 64};

    void exec_offsets(ebpf_inst inst, basic_block_t& block);
    void exec_values(ebpf_inst inst, basic_block_t& block);
    //void jump_offsets(ebpf_inst inst, basic_block_t& block, bool taken);
public:
    constraints(basic_block_t& entry);

    void jump(ebpf_inst inst, basic_block_t& block, bool taken);
    void exec(ebpf_inst inst, basic_block_t& block);
};
#endif
