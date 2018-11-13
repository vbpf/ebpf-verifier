#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

SEC("sk_skb/simple-gt-linux")
int prog_simple_eq_linux(struct __sk_buff *skb)
{
	int *data = (int *)(long)skb->data;
	int *data_end = (int *)(long)skb->data_end;
	if (data+1 >= data_end) return 1;
	data[0] = 0xF;
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = 0x041800;
