#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

SEC("sk_skb/manual-memcpy")
int manual_memcpy(struct __sk_buff *skb)
{
	char *data = (char *)(long)skb->data;
	char *data_end = (char *)(long)skb->data_end;
	long k = data_end - data;
	if (k < 128) {
		volatile char cpy[k];
		while (--k >= 0)
			cpy[k] = data[k];
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = 0x041800;
