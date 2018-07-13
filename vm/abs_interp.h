#pragma once
/*** Interface to the vm.
 true if valid; *errmsg will point to NULL
 false if invalid; *errmsg will point to a heap-allocated error message
*/
#ifdef __cplusplus
extern "C" {
#endif

bool abs_validate(const struct ebpf_inst *insts, uint32_t num_insts, char** errmsg);

#ifdef __cplusplus
}
#endif
