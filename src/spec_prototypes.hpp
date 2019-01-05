#pragma once
// Taken from the linux kernel

enum class Ret {
    INTEGER,
    VOID,
    PTR_TO_MAP_VALUE_OR_NULL
};

enum class Arg {
	/* unused argument in helper function */
	DONTCARE = 0,

	/* the following constraints used to prototype
	 * bpf_map_lookup/update/delete_elem() functions
	 */

	/* const argument used as pointer to bpf_map */
	CONST_MAP_PTR,

	/* pointer to stack used as map key */
	PTR_TO_MAP_KEY,

	/* pointer to stack used as map value */
	PTR_TO_MAP_VALUE,

	/* the following constraints used to prototype bpf_memcmp() and other
	 * functions that access data on eBPF program stack
	 */

	/* pointer to valid memory (stack, packet, map value) */
	PTR_TO_MEM,

	/* pointer to valid memory or NULL */
	PTR_TO_MEM_OR_NULL,
	
	/* pointer to memory does not need to be initialized,
	* helper function must fill all bytes or clear
	* them in error case.
	*/
	PTR_TO_UNINIT_MEM,

	/* number of bytes accessed from memory */
	CONST_SIZE,

	/* number of bytes accessed from memory or 0 */
	CONST_SIZE_OR_ZERO,

	/* pointer to context */
	PTR_TO_CTX,

	/* any (initialized) argument is ok */
	ANYTHING,
};


struct bpf_func_proto {
	const char* name;
	bool pkt_access;
	Ret ret_type;
	Arg arg1_type;
	Arg arg2_type;
	Arg arg3_type;
	Arg arg4_type;
	Arg arg5_type;
};

bpf_func_proto get_prototype(unsigned int n);
bool is_valid_prototype(unsigned int n);
