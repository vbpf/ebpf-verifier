#include "skb.h"

// fails to verify!
// probably an issue with the memory domain

SEC("sk_skb/loop")
int prog(struct __sk_buff *skb)
{
	char *data = (char *)(long)skb->data;
	char *data_end = (char *)(long)skb->data_end;
	long k = data_end - data;
	while (--k >= 0)
		data[k] = (char)k;
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = 0x041800;
