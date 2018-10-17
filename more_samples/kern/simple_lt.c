#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

SEC("sk_skb/simple-lt")
int prog_simple_lt(struct __sk_buff *skb)
{
	char *data = (void *)(long)skb->data;
	char *data_end = (void *)(long)skb->data_end;
	long k = data_end - data;
	if (k < 1) return 1;
	*data = 1;
	return 1;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = 0x041800;
