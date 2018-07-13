#ifndef ABS_CST_REGS_CPP
#define ABS_CST_REGS_CPP

#include <vector>
#include <string>
#include <memory>

#include "ebpf.h"

#include "abs_common.hpp"
#include "abs_cfg.hpp"

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
        var_t region;
        dom_t(variable_factory_t& vfac, int i) :
            value{vfac[std::string("r") + std::to_string(i)], crab::INT_TYPE, 64}, 
            offset{vfac[std::string("off") + std::to_string(i)], crab::INT_TYPE, 64},
            region{vfac[std::string("t") + std::to_string(i)], crab::INT_TYPE, 8}
        { }
    };

    struct array_dom_t {
        var_t values;
        var_t offsets;
        var_t regions;
        array_dom_t(variable_factory_t& vfac, std::string name) :
            values{vfac[std::string(name + "_vals")], crab::ARR_INT_TYPE, 64}, 
            offsets{vfac[std::string(name + "_offsets")], crab::ARR_INT_TYPE, 64},
            regions{vfac[std::string(name + "_regions")], crab::ARR_INT_TYPE, 8}
        { }
        template<typename T>
        void load(basic_block_t& block, dom_t& target, T& offset, int width) {
            block.array_load(target.value, values, offset, width);
            block.array_load(target.offset, offsets, offset, width);
            block.array_load(target.region, regions, offset, width);
        }
        template<typename T>
        void store(basic_block_t& block, T& offset, dom_t& target, int width) {
            block.array_store(values, offset, target.value, width);
            block.array_store(offsets, offset, target.offset, width);
            block.array_store(regions, offset, target.region, width);
        }
    };


    variable_factory_t vfac;	
    std::vector<dom_t> regs;
    array_dom_t stack_arr{vfac, "stack"};
    array_dom_t ctx_arr{vfac, "ctx"};
    array_dom_t data_arr{vfac, "data"};
    var_t pc{vfac[std::string("pc")], crab::INT_TYPE, 16};
    var_t meta_size{vfac[std::string("meta_size")], crab::INT_TYPE, 64};
    var_t total_size{vfac[std::string("data_size")], crab::INT_TYPE, 64};

    static void no_pointer(basic_block_t& block, constraints::dom_t& v);
public:
    constraints(basic_block_t& entry);

    void jump(ebpf_inst inst, basic_block_t& block, bool taken);
    void exec(ebpf_inst inst, basic_block_t& block, basic_block_t& exit, unsigned int pc, cfg_t& cfg);
};
#endif
