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

#ifndef __OVSBPF_HELPERS_H
#define __OVSBPF_HELPERS_H
#include <stdbool.h>
#include <stdio.h>
#include <linux/bpf.h>

/* Additional headers */
# define printk(fmt, ...)                               \
({                                                      \
    char ____fmt[] = fmt;                           \
    bpf_trace_printk(____fmt, sizeof(____fmt),      \
                 ##__VA_ARGS__);                    \
})

#define ERR_EXIT() \
        ({printk("[ERROR] \n"); return TC_ACT_OK;})

#define NOT_HERE() \
        ({printk("[ERROR] Program should not reach here\n");})

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

#define ___constant_swab16(x) ((__u16)(             \
    (((__u16)(x) & (__u16)0x00ffU) << 8) |          \
    (((__u16)(x) & (__u16)0xff00U) >> 8)))

#define ___constant_swab32(x) ((__u32)(             \
    (((__u32)(x) & (__u32)0x000000ffUL) << 24) |        \
    (((__u32)(x) & (__u32)0x0000ff00UL) <<  8) |        \
    (((__u32)(x) & (__u32)0x00ff0000UL) >>  8) |        \
    (((__u32)(x) & (__u32)0xff000000UL) >> 24)))

#define ___constant_swab64(x) ((__u64)(             \
    (((__u64)(x) & (__u64)0x00000000000000ffULL) << 56) |   \
    (((__u64)(x) & (__u64)0x000000000000ff00ULL) << 40) |   \
    (((__u64)(x) & (__u64)0x0000000000ff0000ULL) << 24) |   \
    (((__u64)(x) & (__u64)0x00000000ff000000ULL) <<  8) |   \
    (((__u64)(x) & (__u64)0x000000ff00000000ULL) >>  8) |   \
    (((__u64)(x) & (__u64)0x0000ff0000000000ULL) >> 24) |   \
    (((__u64)(x) & (__u64)0x00ff000000000000ULL) >> 40) |   \
    (((__u64)(x) & (__u64)0xff00000000000000ULL) >> 56)))

#define __constant_htonl(x) (___constant_swab32((x)))
#define __constant_ntohl(x) (___constant_swab32(x))
#define __constant_htons(x) (___constant_swab16((x)))
#define __constant_ntohs(x) ___constant_swab16((x))

/* helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader
 */
#define SEC(NAME) __attribute__((section(NAME), used))

/* helper functions called from eBPF programs written in C */
static void *(*bpf_map_lookup_elem)(void *map, void *key) =
	(void *) BPF_FUNC_map_lookup_elem;
static int (*bpf_map_update_elem)(void *map, void *key, void *value,
				  unsigned long long flags) =
	(void *) BPF_FUNC_map_update_elem;
static int (*bpf_map_delete_elem)(void *map, void *key) =
	(void *) BPF_FUNC_map_delete_elem;
static int (*bpf_probe_read)(void *dst, int size, void *unsafe_ptr) =
	(void *) BPF_FUNC_probe_read;
static unsigned long long (*bpf_ktime_get_ns)(void) =
	(void *) BPF_FUNC_ktime_get_ns;
static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
	(void *) BPF_FUNC_trace_printk;
static void (*bpf_tail_call)(void *ctx, void *map, int index) =
	(void *) BPF_FUNC_tail_call;
static unsigned long long (*bpf_get_smp_processor_id)(void) =
	(void *) BPF_FUNC_get_smp_processor_id;
static unsigned long long (*bpf_get_current_pid_tgid)(void) =
	(void *) BPF_FUNC_get_current_pid_tgid;
static unsigned long long (*bpf_get_current_uid_gid)(void) =
	(void *) BPF_FUNC_get_current_uid_gid;
static int (*bpf_get_current_comm)(void *buf, int buf_size) =
	(void *) BPF_FUNC_get_current_comm;
static int (*bpf_perf_event_read)(void *map, int index) =
	(void *) BPF_FUNC_perf_event_read;
static int (*bpf_clone_redirect)(void *ctx, int ifindex, int flags) =
	(void *) BPF_FUNC_clone_redirect;
static int (*bpf_redirect)(int ifindex, int flags) =
	(void *) BPF_FUNC_redirect;
static int (*bpf_perf_event_output)(void *ctx, void *map,
				    unsigned long long flags, void *data,
				    int size) =
	(void *) BPF_FUNC_perf_event_output;
static int (*bpf_get_stackid)(void *ctx, void *map, int flags) =
	(void *) BPF_FUNC_get_stackid;
static int (*bpf_probe_write_user)(void *dst, void *src, int size) =
	(void *) BPF_FUNC_probe_write_user;
static int (*bpf_current_task_under_cgroup)(void *map, int index) =
	(void *) BPF_FUNC_current_task_under_cgroup;
static int (*bpf_skb_get_tunnel_key)(void *ctx, void *key, int size, int flags) =
	(void *) BPF_FUNC_skb_get_tunnel_key;
static int (*bpf_skb_set_tunnel_key)(void *ctx, void *key, int size, int flags) =
	(void *) BPF_FUNC_skb_set_tunnel_key;
static int (*bpf_skb_get_tunnel_opt)(void *ctx, void *md, int size) =
	(void *) BPF_FUNC_skb_get_tunnel_opt;
static int (*bpf_skb_set_tunnel_opt)(void *ctx, void *md, int size) =
	(void *) BPF_FUNC_skb_set_tunnel_opt;
static unsigned long long (*bpf_get_prandom_u32)(void) =
	(void *) BPF_FUNC_get_prandom_u32;
static int (*bpf_xdp_adjust_head)(void *ctx, int offset) =
	(void *) BPF_FUNC_xdp_adjust_head;
static int (*bpf_skb_vlan_push)(void *ctx, int vlan_proto, int vlan_tci) =
    (void *) BPF_FUNC_skb_vlan_push;
static int (*bpf_skb_vlan_pop)(void *ctx) =
    (void *) BPF_FUNC_skb_vlan_pop;
static int (*bpf_skb_change_tail)(void *ctx, int len, int flags) =
    (void *) BPF_FUNC_skb_change_tail;
static int (*bpf_get_hash_recalc)(void *ctx) =
    (void *) BPF_FUNC_get_hash_recalc;

/* llvm builtin functions that eBPF C program may use to
 * emit BPF_LD_ABS and BPF_LD_IND instructions
 */
struct sk_buff;
unsigned long long load_byte(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.word");

/* a helper structure used by eBPF C program
 * to describe map attributes to elf_bpf loader
 */
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
    unsigned int map_flags;
    unsigned int id;
    unsigned int pinning;
};

/* used in TC */
/*
struct bpf_elf_map {
        __u32 type;
        __u32 key_size;
        __u32 value_size;
        __u32 max_entries;
        __u32 map_flags;
        __u32 id;
        __u32 pinning;
};
*/
static int (*bpf_skb_load_bytes)(void *ctx, int off, void *to, int len) =
	(void *) BPF_FUNC_skb_load_bytes;
static int (*bpf_skb_store_bytes)(void *ctx, int off, void *from, int len, int flags) =
	(void *) BPF_FUNC_skb_store_bytes;
static int (*bpf_l3_csum_replace)(void *ctx, int off, int from, int to, int flags) =
	(void *) BPF_FUNC_l3_csum_replace;
static int (*bpf_l4_csum_replace)(void *ctx, int off, int from, int to, int flags) =
	(void *) BPF_FUNC_l4_csum_replace;
static int (*bpf_skb_under_cgroup)(void *ctx, void *map, int index) =
	(void *) BPF_FUNC_skb_under_cgroup;
static int (*bpf_skb_change_head)(void *, int len, int flags) =
	(void *) BPF_FUNC_skb_change_head;

#if defined(__x86_64__)
#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_RET(x) ((x)->sp)
#define PT_REGS_FP(x) ((x)->bp)
#define PT_REGS_RC(x) ((x)->ax)
#define PT_REGS_SP(x) ((x)->sp)
#define PT_REGS_IP(x) ((x)->ip)
#endif
#define BPF_KPROBE_READ_RET_IP(ip, ctx)		({				\
		bpf_probe_read(&(ip), sizeof(ip), (void *)PT_REGS_RET(ctx)); })
#define BPF_KRETPROBE_READ_RET_IP(ip, ctx)	({				\
		bpf_probe_read(&(ip), sizeof(ip),				\
				(void *)(PT_REGS_FP(ctx) + sizeof(ip))); })
#endif
