#pragma once

#include <vector>
#include <string>

#include "instructions.hpp"
#include "common.hpp"
#include "cfg.hpp"

using crab::cfg_impl::variable_factory_t;
using ikos::z_number;
using debug_info = crab::cfg::debug_info;

using var_t     = ikos::variable<z_number, varname_t>;
using lin_cst_t = ikos::linear_constraint<z_number, varname_t>;

constexpr int STACK_SIZE=512;

struct ptype_descr {
    int size;
    int data = -1;
    int end = -1;
    int meta = -1; // data to meta is like end to data. i.e. meta <= data <= end
};

enum region_t {
    T_UNINIT,
    T_NUM,
    T_CTX,
    T_STACK,
    T_DATA,
    T_MAP,
};

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

    static void assert_init(basic_block_t& block, dom_t& target, crab::cfg::debug_info di)
    {
        block.assertion(target.region >= T_NUM, di);
    }

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
        void load(basic_block_t& block, dom_t& target, const T& offset, int width) {
            block.array_load(target.value, values, offset, width);
            block.array_load(target.region, regions, offset, width);
            block.array_load(target.offset, offsets, offset, width);
        }
        
        template<typename T>
        void store(basic_block_t& block, T& offset, dom_t& target, int width, debug_info di) {
            assert_init(block, target, di);
            block.array_store(values, offset, target.value, width);
            block.array_store(regions, offset, target.region, width);
            block.array_store(offsets, offset, target.offset, width);
        }
    };

    ptype_descr ctx_desc;
    variable_factory_t& vfac;
    std::vector<dom_t> regs;
    array_dom_t stack_arr{vfac, "stack"};
    array_dom_t ctx_arr{vfac, "ctx"};
    array_dom_t data_arr{vfac, "data"};
    var_t meta_size{vfac[std::string("meta_size")], crab::INT_TYPE, 64};
    var_t total_size{vfac[std::string("total_data_size")], crab::INT_TYPE, 64};
    var_t top{vfac[std::string("*")], crab::INT_TYPE, 64};

    void scratch_regs(basic_block_t& block);
    static void no_pointer(basic_block_t& block, constraints::dom_t& v);

    bool exec_mem_access(ebpf_inst inst, basic_block_t& block, basic_block_t& exit, unsigned int pc, cfg_t& cfg);
    void exec_stack_access(ebpf_inst inst, basic_block_t& block, basic_block_t& exit, unsigned int pc, cfg_t& cfg);
    void exec_ctx_access(ebpf_inst inst, basic_block_t& block, basic_block_t& exit, unsigned int pc, cfg_t& cfg);
    void exec_map_access(ebpf_inst inst, basic_block_t& block, basic_block_t& exit, unsigned int pc, cfg_t& cfg);
    void exec_data_access(ebpf_inst inst, basic_block_t& block, basic_block_t& exit, unsigned int pc, cfg_t& cfg);

    void exec_alu(ebpf_inst inst, basic_block_t& block, basic_block_t& exit, unsigned int pc, cfg_t& cfg);
    void exec_call(ebpf_inst inst, basic_block_t& block, basic_block_t& exit, unsigned int pc, cfg_t& cfg);
public:
    constraints(ebpf_prog_type prog_type, variable_factory_t& vfac);
    void setup_entry(basic_block_t& entry);

    void jump(ebpf_inst inst, basic_block_t& block, bool taken);
    void exec(ebpf_inst inst, basic_block_t& block, basic_block_t& exit, unsigned int pc, cfg_t& cfg);
};
