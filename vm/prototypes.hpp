#pragma once
// Taken from the linux kernel

enum bpf_return_type {
    RET_INTEGER,
    RET_VOID,
    RET_PTR_TO_MAP_VALUE_OR_NULL
};

enum bpf_arg_type {
	/* unused argument in helper function */
	ARG_DONTCARE = 0,

	/* the following constraints used to prototype
	 * bpf_map_lookup/update/delete_elem() functions
	 */

	/* const argument used as pointer to bpf_map */
	ARG_CONST_MAP_PTR,

	/* pointer to stack used as map key */
	ARG_PTR_TO_MAP_KEY,

	/* pointer to stack used as map value */
	ARG_PTR_TO_MAP_VALUE,

	/* the following constraints used to prototype bpf_memcmp() and other
	 * functions that access data on eBPF program stack
	 */

	/* pointer to valid memory (stack, packet, map value) */
	ARG_PTR_TO_MEM,

	/* pointer to valid memory or NULL */
	ARG_PTR_TO_MEM_OR_NULL,
	
	/* pointer to memory does not need to be initialized,
	* helper function must fill all bytes or clear
	* them in error case.
	*/
	ARG_PTR_TO_UNINIT_MEM,

	/* number of bytes accessed from memory */
	ARG_CONST_SIZE,

	/* number of bytes accessed from memory or 0 */
	ARG_CONST_SIZE_OR_ZERO,

	/* pointer to context */
	ARG_PTR_TO_CTX,

	/* any (initialized) argument is ok */
	ARG_ANYTHING,
};


struct bpf_func_proto {
	bool pkt_access;
	bpf_return_type ret_type;
	bpf_arg_type arg1_type;
	bpf_arg_type arg2_type;
	bpf_arg_type arg3_type;
	bpf_arg_type arg4_type;
	bpf_arg_type arg5_type;
};

bpf_func_proto get_prototype(unsigned int n);
bool is_valid_prototype(unsigned int n);
