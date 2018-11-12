#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

SEC("sk_skb/simple-lt")
int prog_simple_lt(struct __sk_buff *skb)
{
	long *data = (void *)(long)skb->data;
	long *data_end = (void *)(long)skb->data_end;
	long k = data_end - data;
	if (k <= 48 || k >= 200) return 1;
	*data = 1;
	return 1;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = 0x041800;
