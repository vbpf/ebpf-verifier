#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

SEC("sk_skb/simple-lte")
int prog_simple_lte(struct __sk_buff *skb)
{
	long *data = (void *)(long)skb->data;
	long *data_end = (void *)(long)skb->data_end;
	if (data + 1 <= data_end) {
		*data = 1;
		return 0;
	}
	return 1;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = 0x041800;
