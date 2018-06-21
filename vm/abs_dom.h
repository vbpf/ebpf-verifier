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

#ifndef ABS_DOM_H
#define ABS_DOM_H

#include "ubpf_int.h"

struct abs_dom_value {
    bool known;
    uint64_t value;
    bool bot;
};

extern const struct abs_dom_value abs_dom_top;
extern const struct abs_dom_value abs_dom_bot;

struct abs_dom_value abs_dom_fromconst(uint64_t value);
bool abs_dom_maybe_zero(struct abs_dom_value, bool is64);
struct abs_dom_value abs_dom_join(struct abs_dom_value dst, struct abs_dom_value src);
struct abs_dom_value abs_dom_alu(uint8_t opcode, int32_t imm, struct abs_dom_value dst, struct abs_dom_value src);
void abs_dom_assume(uint8_t opcode, bool taken, struct abs_dom_value *v1, struct abs_dom_value *v2);
struct abs_dom_value abs_dom_call(struct ebpf_inst inst,
    struct abs_dom_value r1,
    struct abs_dom_value r2,
    struct abs_dom_value r3,
    struct abs_dom_value r4,
    struct abs_dom_value r5
);

#endif
