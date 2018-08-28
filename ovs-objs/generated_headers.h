#ifndef P4_GENERATED_HEADERS
#define P4_GENERATED_HEADERS

#define BPF_ENABLE_IPV6

#ifndef BPF_TYPES
#define BPF_TYPES
typedef signed char s8;
typedef unsigned char u8;
typedef signed short s16;
typedef unsigned short u16;
typedef signed int s32;
typedef unsigned int u32;
typedef signed long long s64;
typedef unsigned long long u64;
#endif

struct ipv6_t {
    u8 version; /* 4 bits */
    u8 trafficClass; /* 8 bits */
    u32 flowLabel; /* 20 bits */
    u16 payloadLen; /* 16 bits */
    u8 nextHdr; /* 8 bits */
    u8 hopLimit; /* 8 bits */
    char srcAddr[16]; /* 128 bits */
    char dstAddr[16]; /* 128 bits */
};
struct pkt_metadata_t {
    u32 recirc_id; /* 32 bits */
    u32 dp_hash; /* 32 bits */
    u32 skb_priority; /* 32 bits */
    u32 pkt_mark; /* 32 bits */
    u16 ct_state; /* 16 bits */
    u16 ct_zone; /* 16 bits */
    u32 ct_mark; /* 32 bits */
    char ct_label[16]; /* 128 bits */
    u32 in_port; /* 32 bits */
    u32 packet_length;
};
struct udp_t {
    u16 srcPort; /* 16 bits */
    u16 dstPort; /* 16 bits */
    u16 length_; /* 16 bits */
    u16 checksum; /* 16 bits */
};
struct arp_rarp_t {
    ovs_be16      ar_hrd;	/* format of hardware address   */
    ovs_be16      ar_pro;	/* format of protocol address   */
    unsigned char   ar_hln;	/* length of hardware address   */
    unsigned char   ar_pln;	/* length of protocol address   */
    ovs_be16      ar_op;	/* ARP opcode (command)     */

    /* Ethernet+IPv4 specific members. */
    unsigned char       ar_sha[6];	/* sender hardware address */
    unsigned char       ar_sip[4];	/* sender IP address: be32 */
    unsigned char       ar_tha[6];	/* target hardware address */
    unsigned char       ar_tip[4];	/* target IP address: be32 */
} __attribute__((packed));
struct icmp_t {
    u8 type;
    u8 code;
};
struct icmpv6_t {
    u8 type;
    u8 code;
    u16 csum;
    union {
        uint32_t data32[1]; /* type-specific field */
        uint16_t data16[2]; /* type-specific field */
        uint8_t  data8[4]; /* type-specific field */
    } dataun;
};
struct ipv4_t {
    u8 ttl; /* 8 bits */
    u8 protocol; /* 8 bits */
    ovs_be32 srcAddr; /* 32 bits */
    ovs_be32 dstAddr; /* 32 bits */
};
struct gnv_opt {
    ovs_be16  opt_class;
    uint8_t   type;
    uint8_t   length:5;
    uint8_t   r3:1;
    uint8_t   r2:1;
    uint8_t   r1:1;
    uint8_t   opt_data[4]; /* hard-coded to 4 byte */
};
struct flow_tnl_t {
    union {
        struct {
            u32 ip_dst; /* 32 bits */ // BPF uses host byte-order
            u32 ip_src; /* 32 bits */
        } ip4;
#ifdef BPF_ENABLE_IPV6
        struct {
            char ipv6_dst[16]; /* 128 bits */
            char ipv6_src[16]; /* 128 bits */
        } ip6;
#endif
    };
    u32 tun_id; /* 32 bits */
    u16 flags; /* 16 bits */
    u8 ip_tos; /* 8 bits */
    u8 ip_ttl; /* 8 bits */
    ovs_be16 tp_src; /* 16 bits */
    ovs_be16 tp_dst; /* 16 bits */
    u16 gbp_id; /* 16 bits */
    u8 gbp_flags; /* 8 bits */
    u8 use_ipv6: 4,
       gnvopt_valid: 4;
    struct gnv_opt gnvopt;
    char pad1[0]; /* 40 bits */
};
struct tcp_t {
    ovs_be16 srcPort; /* 16 bits */
    ovs_be16 dstPort; /* 16 bits */
    u32 seqNo; /* 32 bits */
    u32 ackNo; /* 32 bits */
    u8 dataOffset:4, /* 4 bits */
       res:4; /* 4 bits */
    u8 flags; /* 8 bits */
    u16 window; /* 16 bits */
    u16 checksum; /* 16 bits */
    u16 urgentPtr; /* 16 bits */
};
struct ethernet_t {
    char dstAddr[6]; /* 48 bits */
    char srcAddr[6]; /* 48 bits */
    ovs_be16 etherType; /* 16 bits */
};
struct vlan_tag_t {
    union {
        u16 pcp:3,
            cfi:1,
            vid:12;
        ovs_be16 tci;    /* host byte order */
    };
    ovs_be16 etherType;  /* network byte order */
};
struct mpls_t {
    ovs_be32 top_lse; /* top label stack entry */
};

enum proto_valid {
    ETHER_VALID = 1 << 0,
    MPLS_VALID = 1 << 1,
    IPV4_VALID = 1 << 2,
    IPV6_VALID = 1 << 3,
    ARP_VALID = 1 << 4,
    TCP_VALID = 1 << 5,
    UDP_VALID = 1 << 6,
    ICMP_VALID = 1 << 7,
    VLAN_VALID = 1 << 8,
    CVLAN_VALID = 1 << 9,
    ICMPV6_VALID = 1 << 10,
};

struct ebpf_headers_t {
    u32 valid;
    struct ethernet_t ethernet;
    struct mpls_t mpls;
    union {
        struct ipv4_t ipv4;
#ifdef BPF_ENABLE_IPV6
        struct ipv6_t ipv6;
#endif
        struct arp_rarp_t arp;
    };
    union {
        struct tcp_t tcp;
        struct udp_t udp;
        struct icmp_t icmp;
        struct icmpv6_t icmpv6;
    };
    struct vlan_tag_t vlan;
    struct vlan_tag_t cvlan;
};
struct ebpf_metadata_t {
    struct pkt_metadata_t md;
    struct flow_tnl_t tnl_md;
};
#endif
