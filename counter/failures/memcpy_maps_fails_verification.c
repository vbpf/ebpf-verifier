#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"


#define VALUE_SIZE 4098
struct bpf_map_def SEC("maps") m = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = VALUE_SIZE,
	.max_entries = 2,
};

SEC("sk_skb/memcpy-maps")
int memcpy_maps(struct __sk_buff *skb)
{
	int key1 = 0;
	char* value1 = bpf_map_lookup_elem(&m, &key1);
	int key2 = 1;
	char* value2 = bpf_map_lookup_elem(&m, &key2);
	u64 len = skb->len;
	if (!value1 || !value2) return 1;
	volatile long k = 1;

	// "math between map_value pointer and register with unbounded min value is not allowed"
	for (u64 i = 0; i < len; i += 1) {
		long k = i % (VALUE_SIZE - 8);
		value1[k] = value2[k];
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = 0x041800;
