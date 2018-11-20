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
#include <unordered_set>
#include <iostream>

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

static auto build_jump(cfg_t& cfg, pc_t pc, pc_t target, bool taken) -> basic_block_t&
{
    // distinguish taken and non-taken, in case we jump to the fallthrough
    // (yes, it happens).
    basic_block_t& assumption = cfg.insert(label(pc, target) + ":" + (taken ? "taken" : "not-taken"));
    cfg.get_node(exit_label(pc)) >> assumption;
    return assumption;
}

static void link(cfg_t& cfg, pc_t pc, pc_t target)
{
    cfg.get_node(exit_label(pc)) >> cfg.insert(label(target));
}

bool check_raw_reachability(std::vector<ebpf_inst> insts)
{
    std::unordered_set<pc_t> unreachables;
    for (pc_t i=1; i < insts.size(); i++)
        unreachables.insert(i);

    for (pc_t pc = 0; pc < insts.size()-1; pc++) {
        ebpf_inst inst = insts[pc];
        optional<pc_t> jump_target = get_jump(insts[pc], pc);
        optional<pc_t> fall_target = get_fall(insts[pc], pc);
        if (jump_target) {
            unreachables.erase(*jump_target);
        }
        
        if (fall_target) {
            unreachables.erase(*fall_target);
            if (inst.opcode == EBPF_OP_LDDW_IMM)
                unreachables.erase(++pc);
        }
    }
    return unreachables.size() == 0;
}

void print_stats(vector<ebpf_inst> insts) {
    int count = 0;
    int stores = 0;
    int loads = 0;
    int jumps = 0;
    vector<int> reaching(insts.size());
    for (pc_t pc = 0; pc < insts.size()-1; pc++) {
        count++;
        if (is_load(insts[pc].opcode))
            loads++;
        if (is_store(insts[pc].opcode))
            stores++;
        optional<pc_t> fall_target = get_fall(insts[pc], pc);
        optional<pc_t> jump_target = get_jump(insts[pc], pc);
        if (jump_target) {
            reaching[*jump_target]++;
            jumps++;
        }
        if (fall_target) {
            reaching[*fall_target]++;
            pc = *fall_target - 1;
        }
    }
    int joins = 0;
    for (int n : reaching)
        if (n > 1) joins++;

    std::cout << "instructions:" << count << "\n";
    std::cout << "loads:" << loads << "\n";
    std::cout << "stores:" << stores << "\n";
    std::cout << "jumps:" << jumps << "\n";
    std::cout << "joins:" << joins << "\n";
}


void build_cfg(cfg_t& cfg, variable_factory_t& vfac, vector<ebpf_inst> insts, ebpf_prog_type prog_type)
{
    abs_machine_t machine(prog_type, vfac);
    {
        auto& entry = cfg.insert(entry_label());
        machine.setup_entry(entry);
        entry >> cfg.insert(label(0));
    }
    insts.emplace_back();
    for (pc_t pc = 0; pc < insts.size()-1; pc++) {
        ebpf_inst inst = insts[pc];

        vector<basic_block_t*> outs = machine.exec(inst, insts[pc + 1], cfg.insert(label(pc)), cfg);
        basic_block_t& exit = cfg.insert(exit_label(pc));
        for (basic_block_t* b : outs)
            (*b) >> exit;

        if (inst.opcode == EBPF_OP_EXIT) {
            cfg.set_exit(exit_label(pc));
            continue;
        }

        optional<pc_t> jump_target = get_jump(insts[pc], pc);
        optional<pc_t> fall_target = get_fall(insts[pc], pc);
        if (jump_target) {
            if (inst.opcode != EBPF_OP_JA)  {
                auto& assumption = build_jump(cfg, pc, *jump_target, true);
                basic_block_t& out = machine.jump(inst, true, assumption, cfg);
                out >> cfg.insert(label(*jump_target));
            } else {
                link(cfg, pc, *jump_target);
            }
        }
        
        if (fall_target) {
            if (jump_target) {
                auto& assumption = build_jump(cfg, pc, *fall_target, false);
                basic_block_t& out = machine.jump(inst, false, assumption, cfg);
                out >> cfg.insert(label(*fall_target));
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
