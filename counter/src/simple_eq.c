#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

SEC("sk_skb/simple-eq-linux")
int prog_simple_eq_linux(struct __sk_buff *skb)
{
	char *data = (char *)(long)skb->data;
	char *data_end = (char *)(long)skb->data_end;
	if (data == data_end) return 1;
	data[0] = (char)0xF;
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = 0x041800;
