/*
 * Copyright 2018 VMware, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>  // free / calloc
#include <inttypes.h>
#include <assert.h>

#include "abs_interp.h"
#include "abs_state.h"

#include <crab/config.h>
#include <crab/common/types.hpp>
#include <crab/common/debug.hpp>
#include <crab/cfg/cfg.hpp>
#include <crab/cfg/cfg_bgl.hpp>
#include <crab/cg/cg.hpp>
#include <crab/cg/cg_bgl.hpp> 
#include <crab/cfg/var_factory.hpp>

#include <vector>
using std::vector;


namespace crab {

  namespace cfg_impl {

    /// BEGIN MUST BE DEFINED BY CRAB CLIENT
    // A variable factory based on integers
    using variable_factory_t = cfg::var_factory_impl::int_variable_factory;
    using varname_t = typename variable_factory_t::varname_t;
    using basic_block_label_t = std::pair<uint16_t, uint16_t>;
    template<> inline std::string get_label_str(basic_block_label_t e) { return std::to_string(e.first) + "-" + std::to_string(e.second); }
    /// END MUST BE DEFINED BY CRAB CLIENT    

  }
}
using crab::cfg_impl::variable_factory_t;
using crab::cfg_impl::varname_t;
using crab::cfg_impl::basic_block_label_t;

/// CFG over integers
using cfg_t = crab::cfg::Cfg<crab::cfg_impl::basic_block_label_t, crab::cfg_impl::varname_t, ikos::z_number>;
using cfg_ref_t = crab::cfg::cfg_ref<cfg_t>;
using cfg_rev_t = crab::cfg::cfg_rev<cfg_ref_t>;
using basic_block_t = cfg_t::basic_block_t;
using var = ikos::variable<ikos::z_number, crab::cfg_impl::varname_t>;
using lin_t = ikos::linear_expression<ikos::z_number, crab::cfg_impl::varname_t>;
using lin_cst_t = ikos::linear_constraint<ikos::z_number, crab::cfg_impl::varname_t>;

static bool
is_jmp(struct ebpf_inst inst, uint16_t pc, uint16_t* out_target) {
    if ((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_JMP
            && inst.opcode != EBPF_OP_CALL
            && inst.opcode != EBPF_OP_EXIT) {
        *out_target = pc + 1 + inst.offset;
        return true;
    }
    return false;
}

static bool
has_fallthrough(struct ebpf_inst inst, uint16_t pc, uint16_t* out_target) {
    if (inst.opcode != EBPF_OP_JA && inst.opcode != EBPF_OP_EXIT) {
        /* eBPF has one 16-byte instruction: BPF_LD | BPF_DW | BPF_IMM which consists
        of two consecutive 'struct ebpf_inst' 8-byte blocks and interpreted as single
        instruction that loads 64-bit immediate value into a dst_reg. */
        if (inst.opcode == EBPF_OP_LDDW) {
            pc++;
        }
        *out_target = pc + 1;
        return true;
    }
    return false;
}

static basic_block_label_t
label(uint16_t pc)
{
    return {pc, pc};
}

static basic_block_label_t
label(uint16_t pc, uint16_t target)
{
    return {pc, target};
}

static void
build_cfg(const struct ebpf_inst *insts, uint32_t num_insts)
{
    // nodes are named based on the pc just before the instruction
    // assumption nodes are named as {jmp, target}
    cfg_t cfg(label(0));

    variable_factory_t vfac;	
    var r0(vfac[0], crab::INT_TYPE, 64);

    for (uint16_t pc = 0; pc < num_insts; pc++) {
        uint16_t target;
        bool jmp = is_jmp(insts[pc], pc, &target);
        if (jmp) {
            if (insts[pc].opcode != EBPF_OP_JA)  {
                basic_block_t& assumption = cfg.insert(label(pc, target));
                cfg.get_node(label(pc)) >> assumption;
                assumption >> cfg.get_node(label(target));

                assumption.assume(r0 <= r0);
            } else {
                cfg.get_node(label(pc)) >> cfg.get_node(label(target));
            }
        }
        if (has_fallthrough(insts[pc], pc, &target)) {
            if (jmp) {
                basic_block_t& assumption = cfg.insert(label(pc, target));
                cfg.get_node(label(pc)) >> assumption;
                assumption >> cfg.get_node(label(target));

                assumption.assume(r0 > r0);
            } else {
                cfg.get_node(label(pc)) >> cfg.get_node(label(target));
            }
            // skip imm of lddw
            pc = target - 1;
        }
    }
    return ;
}

bool
abs_validate(const struct ebpf_inst *insts, uint32_t num_insts, char** errmsg)
{
    build_cfg(insts, num_insts);
    return false;
}
