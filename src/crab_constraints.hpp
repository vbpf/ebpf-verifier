#pragma once

#include <memory>

#include "common.hpp"
#include "crab_cfg.hpp"

#include "asm.hpp"

using crab::cfg_impl::variable_factory_t;

struct machine_t;

class abs_machine_t
{
    std::unique_ptr<machine_t> impl;
public:
    abs_machine_t(ebpf_prog_type prog_type, variable_factory_t& vfac);
    void setup_entry(basic_block_t& entry);
    vector<basic_block_t*> expand_lockadd(LockAdd lock, basic_block_t& block, cfg_t& cfg);
    std::vector<basic_block_t*> exec(Instruction ins, basic_block_t& block, cfg_t& cfg);
    ~abs_machine_t();
};
