
#ifndef UBPF_VM_AI_H
#define UBPF_VM_AI_H

#include "ubpf_int.h"

struct abs_state {
    uint64_t reg[16];
    bool known[16];
};

bool ai_validate(const struct ebpf_inst *insts, uint32_t num_insts, void *ctx);

void abs_initialize_state(struct abs_state *state, void *ctx, void *stack);
void abs_join_all(struct abs_state *state, struct abs_state *more_states, uint32_t num_more_states);
bool abs_bounds_check(struct abs_state *state, struct ebpf_inst inst);
void abs_execute_assume(struct abs_state *state, struct ebpf_inst inst, bool taken);
void abs_execute(struct abs_state *state, struct ebpf_inst inst);

#endif
