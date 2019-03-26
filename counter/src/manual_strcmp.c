#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"


#define VALUE_SIZE 512

struct bpf_map_def SEC("maps") m1 = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = VALUE_SIZE,
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") m2 = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = VALUE_SIZE,
	.max_entries = 1,
};

SEC("sk_skb/manual-strcmp")
int manual_strcmp(struct __sk_buff *skb)
{
	u32 key1 = 1;
	u32 key2 = 2;
	char* value1;
	char* value2;
	value1 = bpf_map_lookup_elem(&m1, &key1);
	value2 = bpf_map_lookup_elem(&m2, &key2);
	if (!value1 || !value2) return 1;
	int res = 1;
#pragma clang loop unroll_count(513)
	for (int i = 0; i < VALUE_SIZE; i++) {
		if (value1[i] != value2[i]) {
			res = 0;
			break;
		}
		if (value1[i] == '\0')
			break;
	}
	return res;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = 0x041800;
