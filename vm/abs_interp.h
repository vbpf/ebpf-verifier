#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include "ubpf_int.h"

/*** Interface to the loader.
 true if valid; *errmsg will point to NULL
 false if invalid; *errmsg will point to a heap-allocated error message
*/
bool abs_validate(const struct ebpf_inst *insts, uint32_t num_insts, const char* analyzer_name, char** errmsg);

#ifdef __cplusplus
}
#endif
