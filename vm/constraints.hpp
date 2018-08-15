#pragma once

#include <memory>

#include "instructions.hpp"
#include "common.hpp"
#include "cfg.hpp"

using crab::cfg_impl::variable_factory_t;

struct machine_t;

class abs_machine_t
{
    std::unique_ptr<machine_t> impl;
public:
    abs_machine_t(ebpf_prog_type prog_type, variable_factory_t& vfac);
    void setup_entry(basic_block_t& entry);
    void jump(ebpf_inst inst, basic_block_t& block, bool taken);
    void exec(ebpf_inst inst, ebpf_inst next_inst, basic_block_t& block, basic_block_t& exit, cfg_t& cfg);
    ~abs_machine_t();
};
