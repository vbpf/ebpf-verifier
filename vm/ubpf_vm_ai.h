
#ifndef UBPF_VM_AI_H
#define UBPF_VM_AI_H

#include "ubpf_int.h"

struct abs_state {
    uint64_t reg[16];
    bool known[16];
};

extern const struct abs_state abs_bottom;

bool ai_validate(const struct ebpf_inst *insts, uint32_t num_insts, void *ctx, char** errmsg);

void abs_initialize_state(struct abs_state *state, void *ctx, void *stack);
void abs_join(struct abs_state *state, struct abs_state other);
bool abs_bounds_check(struct abs_state *state, struct ebpf_inst inst);
struct abs_state abs_execute_assume(struct abs_state *state, struct ebpf_inst inst, bool taken);
struct abs_state abs_execute(struct abs_state *state, struct ebpf_inst inst);

#endif
