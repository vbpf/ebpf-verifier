#include "skb.h"

SEC("sk_skb/manual-memset")
int manual_memset(struct __sk_buff *skb) {
    char* p = (char*)(long)skb->data_end;
    char* data = (char*)(long)skb->data;
    while (--p >= data) {
        *p = 0xF;
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0x041900;
