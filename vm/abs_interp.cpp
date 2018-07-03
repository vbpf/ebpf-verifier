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
#include <string>

#include <boost/optional.hpp>

using boost::optional;
using std::vector;
using std::to_string;

namespace crab {

  namespace cfg_impl {

    /// BEGIN MUST BE DEFINED BY CRAB CLIENT
    // A variable factory based on strings
    using variable_factory_t = cfg::var_factory_impl::str_variable_factory;
    using varname_t = typename variable_factory_t::varname_t;
    using basic_block_label_t = std::string;
    template<> inline std::string get_label_str(basic_block_label_t e) { return e; }
    /// END MUST BE DEFINED BY CRAB CLIENT    

  }
}
using crab::cfg_impl::variable_factory_t;
using crab::cfg_impl::varname_t;
using crab::cfg_impl::basic_block_label_t;
using ikos::z_number;

/// CFG over integers
using cfg_t         = crab::cfg::Cfg<basic_block_label_t, varname_t, z_number>;
using basic_block_t = cfg_t::basic_block_t;
using var           = ikos::variable<z_number, varname_t>;
using lin_cst_t     = ikos::linear_constraint<z_number, varname_t>;

static optional<uint16_t>
is_jmp(struct ebpf_inst inst, uint16_t pc)
{
    if ((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_JMP
            && inst.opcode != EBPF_OP_CALL
            && inst.opcode != EBPF_OP_EXIT) {
        return pc + 1 + inst.offset;
    }
    return boost::none;
}

static optional<uint16_t>
has_fallthrough(struct ebpf_inst inst, uint16_t pc)
{
    if (inst.opcode != EBPF_OP_JA && inst.opcode != EBPF_OP_EXIT) {
        /* eBPF has one 16-byte instruction: BPF_LD | BPF_DW | BPF_IMM which consists
        of two consecutive 'struct ebpf_inst' 8-byte blocks and interpreted as single
        instruction that loads 64-bit immediate value into a dst_reg. */
        if (inst.opcode == EBPF_OP_LDDW) {
            pc++;
        }
        return pc + 1;
    }
    return boost::none;
}

static basic_block_label_t
label(uint16_t pc)
{
    return to_string(pc);
}

static basic_block_label_t
label(uint16_t pc, uint16_t target)
{
    return to_string(pc) + "-" + to_string(target);
}

static void
build_jmp(cfg_t& cfg, uint16_t pc, uint16_t target, lin_cst_t cst)
{
    basic_block_t& assumption = cfg.insert(label(pc, target));
    cfg.get_node(label(pc)) >> assumption;
    assumption >> cfg.insert(label(target));
    assumption.assume(cst);
}

static void
link(cfg_t& cfg, uint16_t pc, uint16_t target)
{
    cfg.get_node(label(pc)) >> cfg.insert(label(target));
}

bool
abs_validate(const struct ebpf_inst *insts, uint32_t num_insts, char** errmsg)
{
    // nodes are named based on the pc just before the instruction
    // assumption nodes are named "pc-target"
    cfg_t cfg(label(0));

    variable_factory_t vfac;	
    var r0(vfac["r0"], crab::INT_TYPE, 64);

    for (uint16_t pc = 0; pc < num_insts; pc++) {
        optional<uint16_t> jmp_target = is_jmp(insts[pc], pc);
        optional<uint16_t> fall_target = has_fallthrough(insts[pc], pc);
        if (jmp_target) {
            if (insts[pc].opcode != EBPF_OP_JA)  {
                build_jmp(cfg, pc, *jmp_target, r0 <= r0);
            } else {
                link(cfg, pc, *jmp_target);
            }
        }
        if (fall_target) {
            if (jmp_target) {
                build_jmp(cfg, pc, *fall_target, r0 > r0);
            } else {
                link(cfg, pc, *fall_target);
            }
            // skip imm of lddw
            pc = *fall_target - 1;
        }
    }
    return false;
}
