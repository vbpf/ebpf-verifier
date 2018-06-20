
#ifndef UBPF_VM_AI_H
#define UBPF_VM_AI_H

#include "ubpf_int.h"

struct abs_dom_const {
    bool known;
    uint64_t value;
};

struct abs_state {
    struct abs_dom_const reg[16];
    bool bot;
};

bool abs_validate(const struct ebpf_inst *insts, uint32_t num_insts, char** errmsg);

void abs_initialize_state(struct abs_state *state);
void abs_join(struct abs_state *state, struct abs_state other);

bool abs_bounds_fail(struct abs_state *state, struct ebpf_inst inst, uint16_t pc, char** errmsg);
bool abs_divzero_fail(struct abs_state *state, struct ebpf_inst inst, uint16_t pc, char** errmsg);

struct abs_state abs_execute_assume(struct abs_state *state, struct ebpf_inst inst, bool taken);
struct abs_state abs_execute(struct abs_state *state, struct ebpf_inst inst);

void abs_print(struct abs_state *state, const char* s);
#endif
