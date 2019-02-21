#include "skb.h"

SEC("sk_skb/manual-memset")
int manual_memset(struct __sk_buff *skb) {
    long* data_end = (void*)(long)skb->data_end;
    long* data = (void*)(long)skb->data;
    // volatile increment to avoid peeling/unrolling
    volatile long k = 1;
    while (data + 8 <= data_end) {
        *data = 0xFFFFFFFF;
        data += k;
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0x041900;
