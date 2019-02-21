#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"


struct bpf_map_def SEC("maps") m = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = 1,
	.max_entries = 1,
};

SEC("sk_skb/checksum")
int prog(struct __sk_buff *skb)
{
	int key = 1;
	unsigned char* p = bpf_map_lookup_elem(&m, &key);
	if (!p) return 1;
	unsigned char expected = *p;

	char *data = (void *)(long)skb->data;
	char *data_end = (void *)(long)skb->data_end;
	volatile long k = 1;

	unsigned char actual = 0;
	while (data + 8 < data_end) {
		actual += *data;
		data += k;
	}
	return actual == expected ? 0 : 1;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = 0x041800;
