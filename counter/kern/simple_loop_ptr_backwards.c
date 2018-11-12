#include "skb.h"

SEC("sk_skb/loop-ptr")
int prog(struct __sk_buff *skb)
{
	char *data = (void *)(long)skb->data;
	long *data_end = (void *)(long)skb->data_end;

	while (--data_end >= data)
		*data_end = 15;
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = 0x041800;
