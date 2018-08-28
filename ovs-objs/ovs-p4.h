/*
 * Copyright (c) 2016 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#ifndef BPFP4_OPENVSWITCH_H
#define BPFP4_OPENVSWITCH_H 1

#include "helpers.h"
#include "generated_headers.h"
/*
 * From BCC src/cc/export/helpers.h
 */
#define MASK(_n) ((_n) < 64 ? (1ull << (_n)) - 1 : ((u64)-1LL))
#define MASK128(_n) ((_n) < 128 ? ((unsigned __int128)1 << (_n)) - 1 : ((unsigned __int128)-1))

static inline u16 bpf_ntohs(u16 val) {
  /* will be recognized by gcc into rotate insn and eventually rolw 8 */
  return (val << 8) | (val >> 8);
}
static inline u32 bpf_ntohl(u32 val) {
  /* gcc will use bswapsi2 insn */
  return __builtin_bswap32(val);
}
static inline u64 bpf_ntohll(u64 val) {
  /* gcc will use bswapdi2 insn */
  return __builtin_bswap64(val);
}
static inline u16 bpf_htons(u16 val) {
  return bpf_ntohs(val);
}
static inline u32 bpf_htonl(u32 val) {
  return bpf_ntohl(val);
}
static inline u64 bpf_htonll(u64 val) {
  return bpf_ntohll(val);
}
static inline u64 load_dword(void *skb, u64 off) {
    return ((u64)load_word(skb, off) << 32) | load_word(skb, off + 4);
}

static inline __attribute__((always_inline))
void bpf_dins_pkt(void *pkt, u64 off, u64 bofs, u64 bsz, u64 val) {
  // The load_xxx function does a bswap before returning the short/word/dword,
  // so the value in register will always be host endian. However, the bytes
  // written back need to be in network order.
  if (bofs == 0 && bsz == 8) {
    bpf_skb_store_bytes(pkt, off, &val, 1, 0);
  } else if (bofs + bsz <= 8) {
    u8 v = load_byte(pkt, off);
    v &= ~(MASK(bsz) << (8 - (bofs + bsz)));
    v |= ((val & MASK(bsz)) << (8 - (bofs + bsz)));
    bpf_skb_store_bytes(pkt, off, &v, 1, 0);
  } else if (bofs == 0 && bsz == 16) {
    u16 v = bpf_htons(val);
    bpf_skb_store_bytes(pkt, off, &v, 2, 0);
  } else if (bofs + bsz <= 16) {
    u16 v = load_half(pkt, off);
    v &= ~(MASK(bsz) << (16 - (bofs + bsz)));
    v |= ((val & MASK(bsz)) << (16 - (bofs + bsz)));
    v = bpf_htons(v);
    bpf_skb_store_bytes(pkt, off, &v, 2, 0);
  } else if (bofs == 0 && bsz == 32) {
    u32 v = bpf_htonl(val);
    bpf_skb_store_bytes(pkt, off, &v, 4, 0);
  } else if (bofs + bsz <= 32) {
    u32 v = load_word(pkt, off);
    v &= ~(MASK(bsz) << (32 - (bofs + bsz)));
    v |= ((val & MASK(bsz)) << (32 - (bofs + bsz)));
    v = bpf_htonl(v);
    bpf_skb_store_bytes(pkt, off, &v, 4, 0);
  } else if (bofs == 0 && bsz == 64) {
    u64 v = bpf_htonll(val);
    bpf_skb_store_bytes(pkt, off, &v, 8, 0);
  } else if (bofs + bsz <= 64) {
    u64 v = load_dword(pkt, off);
    v &= ~(MASK(bsz) << (64 - (bofs + bsz)));
    v |= ((val & MASK(bsz)) << (64 - (bofs + bsz)));
    v = bpf_htonll(v);
    bpf_skb_store_bytes(pkt, off, &v, 8, 0);
  }
}

enum ErrorCode {
    p4_pe_no_error,
    p4_pe_index_out_of_bounds,
    p4_pe_out_of_packet,
    p4_pe_header_too_long,
    p4_pe_header_too_short,
    p4_pe_unhandled_select,
    p4_pe_checksum,
    p4_pe_too_many_encap,
    p4_pe_ipv6_disabled,
};

#define EBPF_MASK(t, w) ((((t)(1)) << (w)) - (t)1)
#define BYTES(w) ((w + 7) / 8)

#endif
