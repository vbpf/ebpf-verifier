#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"


#define VALUE_SIZE 5
struct bpf_map_def SEC("maps") m = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = VALUE_SIZE,
	.max_entries = 2,
};

SEC("sk_skb/manual-strcmp")
int manual_strcmp(struct __sk_buff *skb)
{
	int key1 = 0;
	char* value1 = bpf_map_lookup_elem(&m, &key1);
	int key2 = 1;
	char* value2 = bpf_map_lookup_elem(&m, &key2);
	u64 len = skb->len;
	if (!value1 || !value2) return 1;
	int res = 1;
#pragma clang loop unroll(full)
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
