// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "catch.hpp"
#include "ebpf_verifier.hpp"

#define FAIL_LOAD_ELF(dirname, filename, sectionname) \
    TEST_CASE("Try loading nonexisting program: " dirname "/" filename, "[elf]") { \
        try { \
            read_elf("ebpf-samples/" dirname "/" filename, sectionname, nullptr, &g_ebpf_platform_linux); \
            REQUIRE(false); \
        } catch (const std::runtime_error&) { \
        }\
    }

// Some intentional failures
FAIL_LOAD_ELF("cilium", "not-found.o", "2/1")
FAIL_LOAD_ELF("cilium", "bpf_lxc.o", "not-found")


#define VERIFY_SECTION(dirname, filename, sectionname, pass) \
    do { \
        auto raw_progs = read_elf("ebpf-samples/" dirname "/" filename, sectionname, nullptr, &g_ebpf_platform_linux); \
        REQUIRE(raw_progs.size() == 1); \
        raw_program raw_prog = raw_progs.back(); \
        std::variant<InstructionSeq, std::string> prog_or_error = unmarshal(raw_prog, &g_ebpf_platform_linux); \
        REQUIRE(std::holds_alternative<InstructionSeq>(prog_or_error)); \
        auto& prog = std::get<InstructionSeq>(prog_or_error); \
        cfg_t cfg = prepare_cfg(prog, raw_prog.info, true); \
        bool res = run_ebpf_analysis(std::cout, cfg, raw_prog.info, nullptr); \
        if (pass)                                            \
            REQUIRE(res);                                    \
        else                                                 \
            REQUIRE(!res);                                   \
    } while (0)

#define TEST_SECTION(project, filename, section) \
    TEST_CASE("./check ebpf-samples/" project "/" filename " " section, "[verify][samples][" project "]") { \
        VERIFY_SECTION(project, filename, section, true); \
    }

#define TEST_SECTION_REJECT(project, filename, section) \
    TEST_CASE("./check ebpf-samples/" project "/" filename " " section, "[verify][samples][" project "]") { \
        VERIFY_SECTION(project, filename, section, false); \
    }

#define TEST_SECTION_FAIL(project, filename, section) \
    TEST_CASE("expect failure ebpf-samples/" project "/" filename " " section, "[!shouldfail][verify][samples][" project "]") { \
        VERIFY_SECTION(project, filename, section, true); \
    }

TEST_SECTION("bpf_cilium_test", "bpf_lxc_jit.o", "1/0xdc06")
TEST_SECTION("bpf_cilium_test", "bpf_lxc_jit.o", "2/1")
TEST_SECTION("bpf_cilium_test", "bpf_lxc_jit.o", "2/3")
TEST_SECTION("bpf_cilium_test", "bpf_lxc_jit.o", "2/4")
TEST_SECTION("bpf_cilium_test", "bpf_lxc_jit.o", "2/5")
TEST_SECTION("bpf_cilium_test", "bpf_lxc_jit.o", "2/6")
TEST_SECTION("bpf_cilium_test", "bpf_lxc_jit.o", "2/7")
TEST_SECTION("bpf_cilium_test", "bpf_lxc_jit.o", "2/10")
TEST_SECTION("bpf_cilium_test", "bpf_lxc_jit.o", "from-container")

TEST_SECTION("bpf_cilium_test", "bpf_lxc-DUNKNOWN.o", "1/0x1010")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DUNKNOWN.o", "2/1")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DUNKNOWN.o", "2/2")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DUNKNOWN.o", "2/3")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DUNKNOWN.o", "2/4")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DUNKNOWN.o", "2/5")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DUNKNOWN.o", "2/6")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DUNKNOWN.o", "2/7")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DUNKNOWN.o", "from-container")

TEST_SECTION("bpf_cilium_test", "bpf_lxc-DDROP_ALL.o", "1/0x1010")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DDROP_ALL.o", "2/1")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DDROP_ALL.o", "2/2")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DDROP_ALL.o", "2/3")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DDROP_ALL.o", "2/4")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DDROP_ALL.o", "2/5")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DDROP_ALL.o", "2/6")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DDROP_ALL.o", "2/7")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DDROP_ALL.o", "from-container")

TEST_SECTION("bpf_cilium_test", "bpf_netdev.o", "2/1")
TEST_SECTION("bpf_cilium_test", "bpf_netdev.o", "2/2")
TEST_SECTION("bpf_cilium_test", "bpf_netdev.o", "2/3")
TEST_SECTION("bpf_cilium_test", "bpf_netdev.o", "2/4")
TEST_SECTION("bpf_cilium_test", "bpf_netdev.o", "2/5")
TEST_SECTION("bpf_cilium_test", "bpf_netdev.o", "2/7")
TEST_SECTION("bpf_cilium_test", "bpf_netdev.o", "from-netdev")

TEST_SECTION("bpf_cilium_test", "bpf_overlay.o", "2/1")
TEST_SECTION("bpf_cilium_test", "bpf_overlay.o", "2/2")
TEST_SECTION("bpf_cilium_test", "bpf_overlay.o", "2/3")
TEST_SECTION("bpf_cilium_test", "bpf_overlay.o", "2/4")
TEST_SECTION("bpf_cilium_test", "bpf_overlay.o", "2/5")
TEST_SECTION("bpf_cilium_test", "bpf_overlay.o", "2/7")
TEST_SECTION("bpf_cilium_test", "bpf_overlay.o", "3/2")
TEST_SECTION("bpf_cilium_test", "bpf_overlay.o", "from-overlay")

TEST_SECTION("bpf_cilium_test", "bpf_lb-DLB_L3.o", "2/1")
TEST_SECTION("bpf_cilium_test", "bpf_lb-DLB_L3.o", "2/2")
TEST_SECTION("bpf_cilium_test", "bpf_lb-DLB_L3.o", "from-netdev")

TEST_SECTION("bpf_cilium_test", "bpf_lb-DLB_L4.o", "2/1")
TEST_SECTION("bpf_cilium_test", "bpf_lb-DLB_L4.o", "2/2")
TEST_SECTION("bpf_cilium_test", "bpf_lb-DLB_L4.o", "from-netdev")

TEST_SECTION("bpf_cilium_test", "bpf_lb-DUNKNOWN.o", "2/1")
TEST_SECTION("bpf_cilium_test", "bpf_lb-DUNKNOWN.o", "2/2")
TEST_SECTION("bpf_cilium_test", "bpf_lb-DUNKNOWN.o", "from-netdev")

TEST_SECTION("cilium", "bpf_lb.o", "2/1")
TEST_SECTION("cilium", "bpf_lb.o", "from-netdev")

TEST_SECTION("cilium", "bpf_lxc.o", "1/0x1010")
TEST_SECTION("cilium", "bpf_lxc.o", "2/1")
TEST_SECTION("cilium", "bpf_lxc.o", "2/3")
TEST_SECTION("cilium", "bpf_lxc.o", "2/4")
TEST_SECTION("cilium", "bpf_lxc.o", "2/5")
TEST_SECTION("cilium", "bpf_lxc.o", "2/6")
TEST_SECTION("cilium", "bpf_lxc.o", "2/7")
TEST_SECTION("cilium", "bpf_lxc.o", "2/8")
TEST_SECTION("cilium", "bpf_lxc.o", "2/9")
TEST_SECTION("cilium", "bpf_lxc.o", "2/10")
TEST_SECTION("cilium", "bpf_lxc.o", "2/11")
TEST_SECTION("cilium", "bpf_lxc.o", "2/12")
TEST_SECTION("cilium", "bpf_lxc.o", "from-container")

TEST_SECTION("cilium", "bpf_netdev.o", "2/1")
TEST_SECTION("cilium", "bpf_netdev.o", "2/3")
TEST_SECTION("cilium", "bpf_netdev.o", "2/4")
TEST_SECTION("cilium", "bpf_netdev.o", "2/5")
TEST_SECTION("cilium", "bpf_netdev.o", "2/7")
TEST_SECTION("cilium", "bpf_netdev.o", "from-netdev")

TEST_SECTION("cilium", "bpf_overlay.o", "2/1")
TEST_SECTION("cilium", "bpf_overlay.o", "2/3")
TEST_SECTION("cilium", "bpf_overlay.o", "2/4")
TEST_SECTION("cilium", "bpf_overlay.o", "2/5")
TEST_SECTION("cilium", "bpf_overlay.o", "2/7")
TEST_SECTION("cilium", "bpf_overlay.o", "from-overlay")

TEST_SECTION("cilium", "bpf_xdp.o", "from-netdev")

TEST_SECTION("linux", "cpustat_kern.o", "tracepoint/power/cpu_frequency")
TEST_SECTION("linux", "cpustat_kern.o", "tracepoint/power/cpu_idle")
TEST_SECTION("linux", "lathist_kern.o", "kprobe/trace_preempt_off")
TEST_SECTION("linux", "lathist_kern.o", "kprobe/trace_preempt_on")
TEST_SECTION("linux", "lwt_len_hist_kern.o", "len_hist")
TEST_SECTION("linux", "map_perf_test_kern.o", "kprobe/sys_getegid")
TEST_SECTION("linux", "map_perf_test_kern.o", "kprobe/sys_geteuid")
TEST_SECTION("linux", "map_perf_test_kern.o", "kprobe/sys_getgid")
TEST_SECTION("linux", "map_perf_test_kern.o", "kprobe/sys_getpgid")
TEST_SECTION("linux", "map_perf_test_kern.o", "kprobe/sys_getppid")
TEST_SECTION("linux", "map_perf_test_kern.o", "kprobe/sys_gettid")
TEST_SECTION("linux", "map_perf_test_kern.o", "kprobe/sys_getuid")
TEST_SECTION("linux", "offwaketime_kern.o", "kprobe/try_to_wake_up")
TEST_SECTION("linux", "offwaketime_kern.o", "tracepoint/sched/sched_switch")
TEST_SECTION("linux", "sampleip_kern.o", "perf_event")
TEST_SECTION("linux", "sock_flags_kern.o", "cgroup/sock1")
TEST_SECTION("linux", "sock_flags_kern.o", "cgroup/sock2")
TEST_SECTION("linux", "sockex1_kern.o", "socket1")
TEST_SECTION("linux", "sockex2_kern.o", "socket2")
TEST_SECTION("linux", "sockex3_kern.o", "socket/3")
TEST_SECTION("linux", "sockex3_kern.o", "socket/4")
TEST_SECTION("linux", "sockex3_kern.o", "socket/1")
TEST_SECTION("linux", "sockex3_kern.o", "socket/2")
TEST_SECTION("linux", "sockex3_kern.o", "socket/0")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/__htab_percpu_map_update_elem")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/_raw_spin_lock")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/_raw_spin_lock_bh")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/_raw_spin_lock_irq")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/_raw_spin_lock_irqsave")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/_raw_spin_trylock_bh")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/_raw_spin_trylock")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/_raw_spin_unlock")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/_raw_spin_unlock_bh")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/_raw_spin_unlock_irqrestore")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/htab_map_alloc")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/htab_map_update_elem")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/mutex_spin_on_owner")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/rwsem_spin_on_owner")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/spin_lock")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/spin_unlock")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/spin_unlock_irqrestore")
TEST_SECTION("linux", "syscall_tp_kern.o", "tracepoint/syscalls/sys_enter_open")
TEST_SECTION("linux", "syscall_tp_kern.o", "tracepoint/syscalls/sys_exit_open")
TEST_SECTION("linux", "task_fd_query_kern.o", "kprobe/blk_start_request")
TEST_SECTION("linux", "task_fd_query_kern.o", "kretprobe/blk_account_io_completion")
TEST_SECTION("linux", "tc_l2_redirect_kern.o", "drop_non_tun_vip")
TEST_SECTION("linux", "tc_l2_redirect_kern.o", "l2_to_ip6tun_ingress_redirect")
TEST_SECTION("linux", "tc_l2_redirect_kern.o", "l2_to_iptun_ingress_forward")
TEST_SECTION("linux", "tc_l2_redirect_kern.o", "l2_to_iptun_ingress_redirect")
TEST_SECTION("linux", "tcp_basertt_kern.o", "sockops")
TEST_SECTION("linux", "tcp_bufs_kern.o", "sockops")
TEST_SECTION("linux", "tcp_cong_kern.o", "sockops")
TEST_SECTION("linux", "tcp_iw_kern.o", "sockops")
TEST_SECTION("linux", "tcbpf1_kern.o", "classifier")
TEST_SECTION("linux", "tcbpf1_kern.o", "clone_redirect_recv")
TEST_SECTION("linux", "tcbpf1_kern.o", "clone_redirect_xmit")
TEST_SECTION("linux", "tcbpf1_kern.o", "redirect_recv")
TEST_SECTION("linux", "tcbpf1_kern.o", "redirect_xmit")
TEST_SECTION("linux", "tcp_clamp_kern.o", "sockops")
TEST_SECTION("linux", "tcp_rwnd_kern.o", "sockops")
TEST_SECTION("linux", "tcp_synrto_kern.o", "sockops")
TEST_SECTION("linux", "test_cgrp2_tc_kern.o", "filter")
TEST_SECTION("linux", "test_current_task_under_cgroup_kern.o", "kprobe/sys_sync")
TEST_SECTION("linux", "test_overhead_kprobe_kern.o", "kprobe/__set_task_comm")
TEST_SECTION("linux", "test_overhead_kprobe_kern.o", "kprobe/urandom_read")
TEST_SECTION("linux", "test_overhead_raw_tp_kern.o", "raw_tracepoint/task_rename")
TEST_SECTION("linux", "test_overhead_raw_tp_kern.o", "raw_tracepoint/urandom_read")
TEST_SECTION("linux", "test_overhead_tp_kern.o", "tracepoint/random/urandom_read")
TEST_SECTION("linux", "test_overhead_tp_kern.o", "tracepoint/task/task_rename")
TEST_SECTION("linux", "test_probe_write_user_kern.o", "kprobe/sys_connect")
TEST_SECTION("linux", "trace_event_kern.o", "perf_event")
TEST_SECTION("linux", "trace_output_kern.o", "kprobe/sys_write")
TEST_SECTION("linux", "tracex1_kern.o", "kprobe/__netif_receive_skb_core")
TEST_SECTION("linux", "tracex2_kern.o", "kprobe/kfree_skb")
TEST_SECTION("linux", "tracex2_kern.o", "kprobe/sys_write")
TEST_SECTION("linux", "tracex3_kern.o", "kprobe/blk_account_io_completion")
TEST_SECTION("linux", "tracex3_kern.o", "kprobe/blk_start_request")
TEST_SECTION("linux", "tracex4_kern.o", "kprobe/kmem_cache_free")
TEST_SECTION("linux", "tracex4_kern.o", "kretprobe/kmem_cache_alloc_node")
TEST_SECTION("linux", "tracex5_kern.o", "kprobe/__seccomp_filter")
TEST_SECTION("linux", "tracex5_kern.o", "kprobe/0")
TEST_SECTION("linux", "tracex5_kern.o", "kprobe/1")
TEST_SECTION("linux", "tracex5_kern.o", "kprobe/9")
TEST_SECTION("linux", "tracex6_kern.o", "kprobe/htab_map_get_next_key")
TEST_SECTION("linux", "tracex6_kern.o", "kprobe/htab_map_lookup_elem")
TEST_SECTION("linux", "tracex7_kern.o", "kprobe/open_ctree")
TEST_SECTION("linux", "xdp_adjust_tail_kern.o", "xdp_icmp")
TEST_SECTION("linux", "xdp_fwd_kern.o", "xdp_fwd")
TEST_SECTION("linux", "xdp_fwd_kern.o", "xdp_fwd_direct")
TEST_SECTION("linux", "xdp_monitor_kern.o", "tracepoint/xdp/xdp_cpumap_enqueue")
TEST_SECTION("linux", "xdp_monitor_kern.o", "tracepoint/xdp/xdp_cpumap_kthread")
TEST_SECTION("linux", "xdp_monitor_kern.o", "tracepoint/xdp/xdp_devmap_xmit")
TEST_SECTION("linux", "xdp_monitor_kern.o", "tracepoint/xdp/xdp_exception")
TEST_SECTION("linux", "xdp_monitor_kern.o", "tracepoint/xdp/xdp_redirect")
TEST_SECTION("linux", "xdp_monitor_kern.o", "tracepoint/xdp/xdp_redirect_err")
TEST_SECTION("linux", "xdp_monitor_kern.o", "tracepoint/xdp/xdp_redirect_map")
TEST_SECTION("linux", "xdp_monitor_kern.o", "tracepoint/xdp/xdp_redirect_map_err")
TEST_SECTION("linux", "xdp_redirect_cpu_kern.o", "xdp_cpu_map0")
TEST_SECTION("linux", "xdp_redirect_cpu_kern.o", "xdp_cpu_map1_touch_data")
TEST_SECTION("linux", "xdp_redirect_cpu_kern.o", "xdp_cpu_map2_round_robin")
TEST_SECTION("linux", "xdp_redirect_cpu_kern.o", "xdp_cpu_map3_proto_separate")
TEST_SECTION("linux", "xdp_redirect_cpu_kern.o", "xdp_cpu_map4_ddos_filter_pktgen")
TEST_SECTION("linux", "xdp_redirect_cpu_kern.o", "xdp_cpu_map5_lb_hash_ip_pairs")
TEST_SECTION("linux", "xdp_redirect_cpu_kern.o", "tracepoint/xdp/xdp_cpumap_enqueue")
TEST_SECTION("linux", "xdp_redirect_cpu_kern.o", "tracepoint/xdp/xdp_cpumap_kthread")
TEST_SECTION("linux", "xdp_redirect_cpu_kern.o", "tracepoint/xdp/xdp_exception")
TEST_SECTION("linux", "xdp_redirect_cpu_kern.o", "tracepoint/xdp/xdp_redirect_err")
TEST_SECTION("linux", "xdp_redirect_cpu_kern.o", "tracepoint/xdp/xdp_redirect_map_err")
TEST_SECTION("linux", "xdp_redirect_kern.o", "xdp_redirect")
TEST_SECTION("linux", "xdp_redirect_kern.o", "xdp_redirect_dummy")
TEST_SECTION("linux", "xdp_redirect_map_kern.o", "xdp_redirect_dummy")
TEST_SECTION("linux", "xdp_redirect_map_kern.o", "xdp_redirect_map")
TEST_SECTION("linux", "xdp_router_ipv4_kern.o", "xdp_router_ipv4")
TEST_SECTION("linux", "xdp_rxq_info_kern.o", "xdp_prog0")
TEST_SECTION("linux", "xdp_sample_pkts_kern.o", "xdp_sample")
TEST_SECTION("linux", "xdp_tx_iptunnel_kern.o", "xdp_tx_iptunnel")
TEST_SECTION("linux", "xdp1_kern.o", "xdp1")
TEST_SECTION("linux", "xdp2_kern.o", "xdp1")
TEST_SECTION("linux", "xdp2skb_meta_kern.o", "tc_mark")
TEST_SECTION("linux", "xdp2skb_meta_kern.o", "xdp_mark")
TEST_SECTION("linux", "xdpsock_kern.o", "xdp_sock")

TEST_SECTION("prototype-kernel", "napi_monitor_kern.o", "tracepoint/irq/softirq_entry")
TEST_SECTION("prototype-kernel", "napi_monitor_kern.o", "tracepoint/irq/softirq_exit")
TEST_SECTION("prototype-kernel", "napi_monitor_kern.o", "tracepoint/irq/softirq_raise")
TEST_SECTION("prototype-kernel", "napi_monitor_kern.o", "tracepoint/napi/napi_poll")
TEST_SECTION("prototype-kernel", "tc_bench01_redirect_kern.o", "ingress_redirect")
TEST_SECTION("prototype-kernel", "xdp_bench01_mem_access_cost_kern.o", "xdp_bench01")
TEST_SECTION("prototype-kernel", "xdp_bench02_drop_pattern_kern.o", "xdp_bench02")
TEST_SECTION("prototype-kernel", "xdp_monitor_kern.o", "tracepoint/xdp/xdp_redirect")
TEST_SECTION("prototype-kernel", "xdp_monitor_kern.o", "tracepoint/xdp/xdp_redirect_err")
TEST_SECTION("prototype-kernel", "xdp_monitor_kern.o", "tracepoint/xdp/xdp_redirect_map_err")
TEST_SECTION("prototype-kernel", "xdp_monitor_kern.o", "tracepoint/xdp/xdp_redirect_map")
TEST_SECTION("prototype-kernel", "xdp_redirect_cpu_kern.o", "xdp_cpu_map0")
TEST_SECTION("prototype-kernel", "xdp_redirect_cpu_kern.o", "xdp_cpu_map2_round_robin")
TEST_SECTION("prototype-kernel", "xdp_redirect_cpu_kern.o", "tracepoint/xdp/xdp_cpumap_enqueue")
TEST_SECTION("prototype-kernel", "xdp_redirect_cpu_kern.o", "tracepoint/xdp/xdp_cpumap_kthread")
TEST_SECTION("prototype-kernel", "xdp_redirect_cpu_kern.o", "tracepoint/xdp/xdp_exception")
TEST_SECTION("prototype-kernel", "xdp_redirect_cpu_kern.o", "tracepoint/xdp/xdp_redirect_err")
TEST_SECTION("prototype-kernel", "xdp_redirect_cpu_kern.o", "tracepoint/xdp/xdp_redirect_map_err")
TEST_SECTION("prototype-kernel", "xdp_redirect_cpu_kern.o", "xdp_cpu_map1_touch_data")
TEST_SECTION("prototype-kernel", "xdp_redirect_cpu_kern.o", "xdp_cpu_map3_proto_separate")
TEST_SECTION("prototype-kernel", "xdp_redirect_cpu_kern.o", "xdp_cpu_map4_ddos_filter_pktgen")
TEST_SECTION("prototype-kernel", "xdp_redirect_cpu_kern.o", "xdp_cpu_map5_ip_l3_flow_hash")
TEST_SECTION("prototype-kernel", "xdp_redirect_err_kern.o", "xdp_redirect_dummy")
TEST_SECTION("prototype-kernel", "xdp_redirect_err_kern.o", "xdp_redirect_map")
TEST_SECTION("prototype-kernel", "xdp_redirect_err_kern.o", "xdp_redirect_map_rr")
TEST_SECTION("prototype-kernel", "xdp_tcpdump_kern.o", "xdp_tcpdump_to_perf_ring")
TEST_SECTION("prototype-kernel", "xdp_ttl_kern.o", "xdp_ttl")
TEST_SECTION("prototype-kernel", "xdp_vlan01_kern.o", "tc_vlan_push")
TEST_SECTION("prototype-kernel", "xdp_vlan01_kern.o", "xdp_drop_vlan_4011")
TEST_SECTION("prototype-kernel", "xdp_vlan01_kern.o", "xdp_vlan_change")
TEST_SECTION("prototype-kernel", "xdp_vlan01_kern.o", "xdp_vlan_remove_outer")
TEST_SECTION("prototype-kernel", "xdp_vlan01_kern.o", "xdp_vlan_remove_outer2")

TEST_SECTION("ovs", "datapath.o", "tail-0")
TEST_SECTION("ovs", "datapath.o", "tail-1")
TEST_SECTION("ovs", "datapath.o", "tail-2")
TEST_SECTION("ovs", "datapath.o", "tail-3")
TEST_SECTION("ovs", "datapath.o", "tail-4")
TEST_SECTION("ovs", "datapath.o", "tail-5")
TEST_SECTION("ovs", "datapath.o", "tail-7")
TEST_SECTION("ovs", "datapath.o", "tail-8")
TEST_SECTION("ovs", "datapath.o", "tail-11")
TEST_SECTION("ovs", "datapath.o", "tail-12")
TEST_SECTION("ovs", "datapath.o", "tail-13")
TEST_SECTION("ovs", "datapath.o", "tail-32")
TEST_SECTION("ovs", "datapath.o", "tail-33")
TEST_SECTION("ovs", "datapath.o", "tail-35")
TEST_SECTION("ovs", "datapath.o", "af_xdp")
TEST_SECTION("ovs", "datapath.o", "downcall")
TEST_SECTION("ovs", "datapath.o", "egress")
TEST_SECTION("ovs", "datapath.o", "ingress")
TEST_SECTION("ovs", "datapath.o", "xdp")

TEST_SECTION("suricata", "bypass_filter.o", "filter")
TEST_SECTION("suricata", "lb.o", "loadbalancer")
TEST_SECTION("suricata", "filter.o", "filter")
TEST_SECTION("suricata", "vlan_filter.o", "filter")
TEST_SECTION("suricata", "xdp_filter.o", "xdp")

// Test some programs that ought to fail verification.
TEST_SECTION_REJECT("build", "badhelpercall.o", ".text")
TEST_SECTION_REJECT("build", "exposeptr.o", ".text")

// Test some programs that ought to fail verification but
// are currently allowed through.  These should be changed
// to TEST_SECTION_REJECT() once fixed.
TEST_SECTION("build", "exposeptr2.o", ".text")
TEST_SECTION("build", "mapoverflow.o", ".text")
TEST_SECTION("build", "mapunderflow.o", ".text")

// The following eBPF programs currently fail verification.
// If the verifier is later updated to accept them, these should
// be changed to TEST_SECTION().

// Unsupported: map-in-map
TEST_SECTION_FAIL("linux", "map_perf_test_kern.o", "kprobe/sys_connect")
TEST_SECTION_FAIL("linux", "test_map_in_map_kern.o", "kprobe/sys_connect")

// Unsupported: ebpf-function
TEST_SECTION_FAIL("prototype-kernel", "xdp_ddos01_blacklist_kern.o", ".text")

// False positive: correlated branches
TEST_SECTION_FAIL("prototype-kernel", "xdp_ddos01_blacklist_kern.o", "xdp_prog")
