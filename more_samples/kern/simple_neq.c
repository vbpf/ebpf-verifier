#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

SEC("sk_skb/simple-neq")
int prog_simple_neq(struct __sk_buff *skb)
{
	char *data = (char *)(long)skb->data;
	char *data_end = (char *)(long)skb->data_end;
	long k = data_end - data;
	if (k != 1) return 1;
	data[0] = (char)0xF;
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = 0x041800;
