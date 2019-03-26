#include "skb.h"

SEC("sk_skb/manual-memset")
int manual_memset(struct __sk_buff *skb) {
    long* p = (void*)(long)skb->data_end;
    long* data = (void*)(long)skb->data;
    while (--p >= data) {
        *p = 0xFFFFFFFF;
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0x041900;
