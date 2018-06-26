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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <assert.h>

#include "ubpf_int.h"
#include "abs_interp.h"
#include "abs_state.h"

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

static int*
compute_pending(const struct ebpf_inst *insts, uint32_t num_insts)
{
    int *pending = calloc(num_insts, sizeof(*pending));
    pending[0] = 1;

    for (uint16_t pc = 0; pc < num_insts; pc++) {
        uint16_t target;
        if (is_jmp(insts[pc], pc, &target)) {
            pending[target]++;
        }
        if (has_fallthrough(insts[pc], pc, &target)) {
            pending[target]++;
            // skip imm of lddw
            pc = target - 1;
        }
    }
    return pending;
}

bool
abs_validate(const struct ebpf_inst *insts, uint32_t num_insts, char** errmsg)
{
    int *pending = compute_pending(insts, num_insts);

    uint16_t available[num_insts];

    // states[i] contains the state just before instruction i
    struct abs_state states[num_insts];
    for (int i = 0; i < num_insts; i++) {
        abs_initialize_unreached(&states[i]);
    }
    
    bool res = true;
    available[0] = 0;
    abs_initialize_entry(&states[0]);

    assert(*errmsg == NULL);

    int wi = 1;
    do {
        const uint16_t pc = available[--wi];
        const struct ebpf_inst inst = insts[pc];

        uint16_t target;
        if (is_jmp(inst, pc, &target)) {
            abs_execute(&states[target], &states[pc], inst, 0, true, pc, errmsg);
            pending[target]--;
            if (pending[target] == 0)
                available[wi++] = target;
        }

        if (*errmsg != NULL) {
            res = false;
            break;
        }
        if (has_fallthrough(inst, pc, &target)) {
            abs_execute(&states[target], &states[pc], inst, insts[pc+1].imm, false, pc, errmsg);
            pending[target]--;
            if (pending[target] == 0)
                available[wi++] = target;
        } 
        if (inst.opcode == EBPF_OP_EXIT) {
            break;
        }
        if (*errmsg != NULL) {
            res = false;
            break;
        }
    } while (wi > 0);

    free(pending);

    return res;
}
