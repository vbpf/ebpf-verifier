
#ifndef UBPF_VM_AI_H
#define UBPF_VM_AI_H

#include "ubpf_int.h"

struct abs_state {
    uint64_t reg[16];
    bool known[16];
    bool bot;
};

extern const struct abs_state abs_bottom;

bool abs_validate(const struct ebpf_inst *insts, uint32_t num_insts, char** errmsg);

void abs_initialize_state(struct abs_state *state);
void abs_join(struct abs_state *state, struct abs_state other);

bool abs_bounds_fail(struct abs_state *state, struct ebpf_inst inst, uint16_t pc, char** errmsg);
bool abs_divzero_fail(struct abs_state *state, struct ebpf_inst inst, uint16_t pc, char** errmsg);

struct abs_state abs_execute_assume(struct abs_state *state, struct ebpf_inst inst, bool taken);
struct abs_state abs_execute(struct abs_state *state, struct ebpf_inst inst);

void abs_print(struct abs_state *state, const char* s);
#endif
