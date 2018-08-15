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

#include <inttypes.h>
#include <assert.h>

#include <vector>
#include <string>
#include <algorithm>

#include <boost/optional.hpp>

#include "common.hpp"
#include "constraints.hpp"
#include "cfg.hpp"
#include "verifier.hpp"

using boost::optional;
using std::to_string;
using std::string;
using std::vector;


using pc_t = uint16_t;

static auto get_jump(struct ebpf_inst inst, pc_t pc) -> optional<pc_t>
{
    if ((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_JMP
            && inst.opcode != EBPF_OP_CALL
            && inst.opcode != EBPF_OP_EXIT) {
        return pc + 1 + inst.offset;
    }
    return boost::none;
}

static auto get_fall(struct ebpf_inst inst, pc_t pc) -> optional<pc_t>
{
    if (inst.opcode != EBPF_OP_JA && inst.opcode != EBPF_OP_EXIT) {
        /* eBPF has one 16-byte instruction: BPF_LD | BPF_DW | BPF_IMM which consists
        of two consecutive 'struct ebpf_inst' 8-byte blocks and interpreted as single
        instruction that loads 64-bit immediate value into a dst_reg. */
        if (inst.opcode == EBPF_OP_LDDW_IMM) {
            pc++;
        }
        return pc + 1;
    }
    return boost::none;
}

static auto build_jump(cfg_t& cfg, pc_t pc, pc_t target) -> basic_block_t&
{
    basic_block_t& assumption = cfg.insert(label(pc, target));
    cfg.get_node(exit_label(pc)) >> assumption;
    assumption >> cfg.insert(label(target));
    return assumption;
}

static void link(cfg_t& cfg, pc_t pc, pc_t target)
{
    cfg.get_node(exit_label(pc)) >> cfg.insert(label(target));
}

void build_cfg(cfg_t& cfg, variable_factory_t& vfac, std::vector<ebpf_inst> insts, ebpf_prog_type prog_type)
{
    abs_machine_t machine(prog_type, vfac);
    {
        auto& entry = cfg.insert(entry_label());
        machine.setup_entry(entry);
        entry >> cfg.insert(label(0));
    }
    insts.emplace_back();
    for (pc_t pc = 0; pc < insts.size()-1; pc++) {
        auto inst = insts[pc];

        machine.exec(inst, insts[pc + 1], cfg.insert(label(pc)), cfg.insert(exit_label(pc)), cfg);

        if (inst.opcode == EBPF_OP_EXIT) {
            cfg.set_exit(exit_label(pc));
            continue;
        }

        optional<pc_t> jump_target = get_jump(insts[pc], pc);
        optional<pc_t> fall_target = get_fall(insts[pc], pc);
        if (jump_target) {
            if (inst.opcode != EBPF_OP_JA)  {
                auto& assumption = build_jump(cfg, pc, *jump_target);
                machine.jump(inst, assumption, true);
            } else {
                link(cfg, pc, *jump_target);
            }
        }
        
        if (fall_target) {
            if (jump_target) {
                auto& assumption = build_jump(cfg, pc, *fall_target);
                machine.jump(inst, assumption, false);
            } else {
                link(cfg, pc, *fall_target);
            }
            // skip imm of lddw
            pc = *fall_target - 1;
        }
    }
    if (global_options.simplify) {
        cfg.simplify();
    }
}

vector<string> sorted_labels(cfg_t& cfg)
{
    vector<string> labels;
    for (const auto& block : cfg)
        labels.push_back(block.label());

    std::sort(labels.begin(), labels.end(), [](string a, string b){
        if (first_num(a) < first_num(b)) return true;
        if (first_num(a) > first_num(b)) return false;
        return a < b;
    });
    return labels;
}
