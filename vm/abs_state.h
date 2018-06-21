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

#ifndef ABS_STATE_H
#define ABS_STATE_H

#include "ubpf_int.h"
#include "abs_dom.h"

struct abs_state {
    struct abs_dom_value reg[16];
    bool bot;
};

void abs_initialize_entry(struct abs_state *state);
void abs_initialize_unreached(struct abs_state *state);

bool abs_bounds_fail(struct abs_state *state, struct ebpf_inst inst, uint16_t pc, char** errmsg);
bool abs_divzero_fail(struct abs_state *state, struct ebpf_inst inst, uint16_t pc, char** errmsg);

void abs_execute_assume(struct abs_state *to, struct abs_state *from, struct ebpf_inst inst, bool taken);
void abs_execute(struct abs_state *to, struct abs_state *from, struct ebpf_inst inst, int32_t imm);

void abs_print(struct abs_state *state, const char* s);

#endif
