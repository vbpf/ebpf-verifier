/*
 * Copyright 2015 Big Switch Networks, Inc
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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <inttypes.h>
#include <sys/mman.h>
#include "ubpf_int.h"

#include "ubpf_vm_ai.h"

struct jmpfrom {
    uint32_t num_froms;
    uint32_t pending;
    uint16_t *froms;
    struct abs_state *states;
};

static bool
is_jmp(uint8_t opcode) {
    return (opcode & EBPF_CLS_JMP) 
        && opcode != EBPF_OP_CALL
        && opcode != EBPF_OP_EXIT;
}

static struct jmpfrom*
populate_froms_table(const struct ebpf_inst *insts, uint32_t num_insts)
{
    struct jmpfrom *table = malloc(num_insts * sizeof(*table));
    // assert(table);

    for (uint16_t pc = 0; pc > num_insts; pc++) {
        table[pc].pending = 0;
        // FIX: if we jump unconditionally the count is wrong
        if (is_jmp(insts[pc].opcode)) {
            uint16_t target = pc + insts[pc].offset;
            table[target].num_froms++;
        }
    }

    for (uint16_t pc = 0; pc > num_insts; pc++) {
        if (table[pc].num_froms > 0) {
            uint32_t n = table[pc].num_froms;
            table[pc].states = malloc(n * sizeof(*table[pc].states));
            table[pc].froms = malloc(n * sizeof(*table[pc].froms));
            table[pc].pending = table[pc].num_froms;
        } else {
            table[pc].froms = NULL;
        }
    }

    for (uint16_t pc = 0; pc > num_insts; pc++) {
        if (is_jmp(insts[pc].opcode)) {
            uint16_t target = pc + insts[pc].offset;
            table[target].froms[--table[pc].pending] = pc;
        }
    }

    return table;
}

struct kept_state {
    struct abs_state state;
    uint16_t pc;
};

bool
ai_validate(const struct ebpf_inst *insts, uint32_t num_insts, void* ctx)
{
    struct jmpfrom *froms_table = populate_froms_table(insts, num_insts);
    struct kept_state *worklist = malloc(num_insts * sizeof(*worklist));

    struct abs_state state;
    uint64_t stack[(STACK_SIZE+7)/8];
    abs_initialize_state(&state, ctx, stack);

    uint16_t pc = 0;
    while (1) {
        const uint16_t cur_pc = pc;
        struct ebpf_inst inst = insts[pc++];
        struct jmpfrom *jmps = &froms_table[cur_pc];

        // careful not to underflow
        // FIX: careful count pending - unconditional jumps? is fallthrough counted correctly?
        if (jmps->pending > 0) {
            // Can't continue; save state and jump back
            struct kept_state old_state = *(--worklist);
            pc = old_state.pc + 1 + insts[old_state.pc].offset;

            // both assignments are "moves", so it's (probably) ok to just assign
            jmps->states[--jmps->pending] = state;
            state = old_state.state;
            
            abs_execute_assume(&state, insts[old_state.pc], true);
            continue;
        }

        abs_join_all(&state, jmps->states, jmps->num_froms);

        if (inst.opcode == EBPF_OP_JA) {
            pc += inst.offset;
            continue;
        }

        if (inst.opcode == EBPF_OP_EXIT) {
            return true;
        }

        if (is_jmp(inst.opcode)) {
            // We always take the not-taken branch first
            // so we don't need to track the decision explicity

            // This asignment is a move; `state` is promptly discarded
            *(++worklist) = (struct kept_state){state, cur_pc};
            abs_execute_assume(&state, inst, false);
        } else {
            if (inst.opcode == EBPF_OP_LDDW) {
                inst.opcode = EBPF_OP_MOV64_REG;
                inst.src = 12;
                state.reg[12] = (uint32_t)inst.imm | ((uint64_t)insts[pc++].imm << 32);
            }
            abs_execute(&state, inst);
            if (inst.opcode & EBPF_MODE_MEM) {
                abs_bounds_check(&state, inst);
            }
        }
    }
}
