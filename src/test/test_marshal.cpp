// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "catch.hpp"

#include "asm_files.hpp"
#include "asm_marshal.hpp"
#include "asm_ostream.hpp"
#include "asm_unmarshal.hpp"

static void compare_marshal_unmarshal(const Instruction& ins, bool double_cmd = false) {
    program_info info{.platform = &g_ebpf_platform_linux,
                      .type = g_ebpf_platform_linux.get_program_type("unspec", "unspec")};
    InstructionSeq parsed = std::get<InstructionSeq>(unmarshal(raw_program{"", "", marshal(ins, 0), info}));
    REQUIRE(parsed.size() == 1);
    auto [_, single, _2] = parsed.back();
    (void)_;  // unused
    (void)_2; // unused
    REQUIRE(single == ins);
}

static const auto ws = {1, 2, 4, 8};

TEST_CASE("disasm_marshal", "[disasm][marshal]") {
    SECTION("Bin") {
        auto ops = {Bin::Op::MOV, Bin::Op::ADD, Bin::Op::SUB, Bin::Op::MUL, Bin::Op::DIV,  Bin::Op::MOD,
                    Bin::Op::OR,  Bin::Op::AND, Bin::Op::LSH, Bin::Op::RSH, Bin::Op::ARSH, Bin::Op::XOR};
        SECTION("Reg src") {
            for (auto op : ops) {
                compare_marshal_unmarshal(Bin{.op = op, .dst = Reg{1}, .v = Reg{2}, .is64 = true});
                compare_marshal_unmarshal(Bin{.op = op, .dst = Reg{1}, .v = Reg{2}, .is64 = false});
            }
        }
        SECTION("Imm src") {
            for (auto op : ops) {
                // .is64=true should fail?
                compare_marshal_unmarshal(Bin{.op = op, .dst = Reg{1}, .v = Imm{2}, .is64 = false});
                compare_marshal_unmarshal(Bin{.op = op, .dst = Reg{1}, .v = Imm{2}, .is64 = true});
            }
            SECTION("LDDW") {
                compare_marshal_unmarshal(
                    Bin{.op = Bin::Op::MOV, .dst = Reg{1}, .v = Imm{2}, .is64 = true, .lddw = true}, true);
            }
        }
    }

    SECTION("Un") {
        auto ops = {
            Un::Op::BE16,
            Un::Op::BE32,
            Un::Op::BE64,
            Un::Op::LE16,
            Un::Op::LE32,
            Un::Op::LE64,
            Un::Op::NEG,
        };
        for (auto op : ops)
            compare_marshal_unmarshal(Un{.op = op, .dst = Reg{1}});
    }

    SECTION("LoadMapFd") { compare_marshal_unmarshal(LoadMapFd{.dst = Reg{1}, .mapfd = 1}, true); }

    SECTION("Jmp") {
        auto ops = {Condition::Op::EQ, Condition::Op::GT, Condition::Op::GE, Condition::Op::SET,
            // Condition::Op::NSET, does not exist in ebpf
                    Condition::Op::NE, Condition::Op::SGT, Condition::Op::SGE, Condition::Op::LT, Condition::Op::LE,
                    Condition::Op::SLT, Condition::Op::SLE};
        SECTION("Reg right") {
            for (auto op : ops) {
                Condition cond{.op = op, .left = Reg{1}, .right = Reg{2}};
                compare_marshal_unmarshal(Jmp{.cond = cond, .target = label_t(1)});
            }
        }
        SECTION("Imm right") {
            for (auto op : ops) {
                Condition cond{.op = op, .left = Reg{1}, .right = Imm{2}};
                compare_marshal_unmarshal(Jmp{.cond = cond, .target = label_t(1)});
            }
        }
    }

    SECTION("Call") {
        for (int func : {1, 17})
            compare_marshal_unmarshal(Call{func});
    }

    SECTION("Exit") { compare_marshal_unmarshal(Exit{}); }

    SECTION("Packet") {
        for (int w : ws) {
            compare_marshal_unmarshal(Packet{.width = w, .offset = 7, .regoffset = {}});
            compare_marshal_unmarshal(Packet{.width = w, .offset = 7, .regoffset = Reg{2}});
        }
    }

    SECTION("LockAdd") {
        for (int w : ws) {
            Deref access{.width = w, .basereg = Reg{2}, .offset = 17};
            compare_marshal_unmarshal(LockAdd{.access = access, .valreg = Reg{1}});
        }
    }
}

TEST_CASE("marshal", "[disasm][marshal]") {
    SECTION("Load") {
        Deref access{.width = 1, .basereg = Reg{4}, .offset = 6};
        Mem m{.access = access, .value = Reg{3}, .is_load = true};
        auto ins = marshal(m, 0).at(0);
        ebpf_inst expect{
            .opcode = (uint8_t)(INST_CLS_LD | (INST_MEM << 5) | width_to_opcode(1) | 0x1),
            .dst = 3,
            .src = 4,
            .offset = 6,
            .imm = 0,
        };
        REQUIRE(ins.dst == expect.dst);
        REQUIRE(ins.src == expect.src);
        REQUIRE(ins.offset == expect.offset);
        REQUIRE(ins.imm == expect.imm);
        REQUIRE(ins.opcode == expect.opcode);
    }
    SECTION("Load Imm") {
        Deref access{.width = 1, .basereg = Reg{4}, .offset = 6};
        REQUIRE_THROWS(marshal(Mem{.access = access, .value = Imm{3}, .is_load = true}, 0));
    }
    SECTION("Store") {
        Deref access{.width = 1, .basereg = Reg{4}, .offset = 6};
        auto ins = marshal(Mem{.access = access, .value = Reg{3}, .is_load = false}, 0).at(0);
        REQUIRE(ins.src == 3);
        REQUIRE(ins.dst == 4);
        REQUIRE(ins.offset == 6);
        REQUIRE(ins.imm == 0);
        REQUIRE(ins.opcode == (uint8_t)(INST_CLS_ST | (INST_MEM << 5) | width_to_opcode(1) | 0x1));
    }
    SECTION("StoreImm") {
        Deref access{.width = 1, .basereg = Reg{4}, .offset = 6};
        auto ins = marshal(Mem{.access = access, .value = Imm{3}, .is_load = false}, 0).at(0);
        REQUIRE(ins.src == 0);
        REQUIRE(ins.dst == 4);
        REQUIRE(ins.offset == 6);
        REQUIRE(ins.imm == 3);
        REQUIRE(ins.opcode == (uint8_t)(INST_CLS_ST | (INST_MEM << 5) | width_to_opcode(1) | 0x0));
    }
}

TEST_CASE("disasm_marshal_Mem", "[disasm][marshal]") {
    SECTION("Load") {
        for (int w : ws) {
            Deref access;
            access.basereg = Reg{4};
            access.offset = 6;
            access.width = w;
            compare_marshal_unmarshal(Mem{.access = access, .value = Reg{3}, .is_load = true});
        }
    }
    SECTION("Store Register") {
        for (int w : ws) {
            Deref access;
            access.basereg = Reg{9};
            access.offset = 8;
            access.width = w;
            compare_marshal_unmarshal(Mem{.access = access, .value = Reg{4}, .is_load = false});
        }
    }
    SECTION("Store Immediate") {
        for (int w : ws) {
            Deref access;
            access.basereg = Reg{10};
            access.offset = 2;
            access.width = w;
            compare_marshal_unmarshal(Mem{.access = access, .value = Imm{5}, .is_load = false});
        }
    }
}

void test_marshal_unmarshal_elf(const std::string& elf_file) {
    auto raw_progs = read_elf(elf_file, "", nullptr, &g_ebpf_platform_linux);
    for (auto& program : raw_progs) {
        auto unmarshal_result = unmarshal(program);
        REQUIRE(std::holds_alternative<InstructionSeq>(unmarshal_result));
        auto instruction_sequence = std::get<InstructionSeq>(unmarshal_result);
        std::vector<Instruction> instructions;
        for (auto& [label, instruction, btf] : std::get<InstructionSeq>(unmarshal_result)) {
            instructions.push_back(instruction);
        }

        auto bpf_instructions = marshal(instructions);
        REQUIRE(bpf_instructions.size() == program.prog.size());
        for (size_t i = 0; i < bpf_instructions.size(); i++) {
            ebpf_inst expected = program.prog[i];
            ebpf_inst result = bpf_instructions[i];
            REQUIRE((uint32_t)expected.opcode == (uint32_t)result.opcode);
            REQUIRE(expected.dst == result.dst);
            REQUIRE(expected.src == result.src);
            REQUIRE(expected.offset == result.offset);
            REQUIRE(expected.imm == result.imm);
        }
    }
}

void test_unmarshal_elf_failure(const std::string& elf_file, const std::string& error) {
    try {
        auto raw_progs = read_elf(elf_file, "", nullptr, &g_ebpf_platform_linux);
    } catch (std::runtime_error& ex) {
        REQUIRE(std::string(ex.what()).find(error) != std::string::npos);
    }
}

#define TEST_UNMARSHAL_MARSHAL(ELF_FILE) \
    TEST_CASE("unmarshal_marshal_" ELF_FILE, "[unmarshal][marshal]") { test_marshal_unmarshal_elf(ELF_FILE); }

#define TEST_UNMARSHAL_FAILURE(ELF_FILE, EXPECTED_ERROR)                \
    TEST_CASE("unmarshal_failure_" ELF_FILE, "[unmarshal][negative]") { \
        test_unmarshal_elf_failure(ELF_FILE, EXPECTED_ERROR);           \
    }

#define TEST_UNMARSHAL_MARSHAL_FAIL(ELF_FILE)                                       \
    TEST_CASE("unmarshal_marshal_" ELF_FILE, "[unmarshal][marshal][!shouldfail]") { \
        test_marshal_unmarshal_elf(ELF_FILE);                                       \
    }

TEST_UNMARSHAL_FAILURE("ebpf-samples/build/badrelo.o", "Unresolved external symbol bpf_map_update_elem");
TEST_UNMARSHAL_FAILURE("ebpf-samples/falco/probe.o", "Unresolved external symbol memset")
TEST_UNMARSHAL_FAILURE("ebpf-samples/new_linux/sockex1_kern.o", "Can't find any maps sections in file")
TEST_UNMARSHAL_FAILURE("ebpf-samples/new_linux/sockex2_kern.o", "Can't find any maps sections in file")
TEST_UNMARSHAL_FAILURE("ebpf-samples/new_linux/sockex3_kern.o", "Can't find any maps sections in file")
TEST_UNMARSHAL_FAILURE("ebpf-samples/new_linux/trace_output_kern.o", "Can't find any maps sections in file")
TEST_UNMARSHAL_FAILURE("ebpf-samples/new_linux/tracex1_kern.o", "Can't find any maps sections in file")
TEST_UNMARSHAL_FAILURE("ebpf-samples/new_linux/tracex2_kern.o", "Can't find any maps sections in file")
TEST_UNMARSHAL_FAILURE("ebpf-samples/new_linux/tracex3_kern.o", "Can't find any maps sections in file")
TEST_UNMARSHAL_FAILURE("ebpf-samples/new_linux/tracex4_kern.o", "Can't find any maps sections in file")
TEST_UNMARSHAL_FAILURE("ebpf-samples/new_linux/tracex6_kern.o", "Can't find any maps sections in file")
TEST_UNMARSHAL_FAILURE("ebpf-samples/new_linux/tracex7_kern.o", "Can't find any maps sections in file")

TEST_UNMARSHAL_MARSHAL("ebpf-samples/bpf_cilium_test/bpf_lb-DLB_L3.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/bpf_cilium_test/bpf_lb-DLB_L4.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/bpf_cilium_test/bpf_lb-DUNKNOWN.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/bpf_cilium_test/bpf_lxc_jit.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/bpf_cilium_test/bpf_lxc-DDROP_ALL.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/bpf_cilium_test/bpf_lxc-DUNKNOWN.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/bpf_cilium_test/bpf_netdev.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/bpf_cilium_test/bpf_overlay.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/build/badhelpercall.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/build/badmapptr.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/build/byteswap.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/build/ctxoffset.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/build/exposeptr.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/build/exposeptr2.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/build/map_in_map.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/build/mapoverflow.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/build/mapunderflow.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/build/mapvalue-overrun.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/build/nullmapref.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/build/packet_access.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/build/packet_overflow.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/build/packet_reallocate.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/build/packet_start_ok.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/build/ringbuf_uninit.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/build/stackok.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/build/tail_call.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/build/tail_call_bad.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/build/twomaps.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/build/twostackvars.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/build/twotypes.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/cilium/bpf_lb.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/cilium/bpf_lxc.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/cilium/bpf_netdev.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/cilium/bpf_overlay.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/cilium/bpf_xdp.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/cilium/bpf_xdp_dsr_linux_v1_1.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/cpustat_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/lathist_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/lwt_len_hist_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/map_perf_test_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/offwaketime_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/sampleip_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/sock_flags_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/sockex1_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/sockex2_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/sockex3_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/spintest_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/syscall_tp_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/task_fd_query_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/tc_l2_redirect_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/tcbpf1_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/tcp_basertt_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/tcp_bufs_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/tcp_clamp_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/tcp_cong_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/tcp_iw_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/tcp_rwnd_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/tcp_synrto_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/test_cgrp2_tc_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/test_current_task_under_cgroup_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/test_map_in_map_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/test_overhead_kprobe_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/test_overhead_raw_tp_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/test_overhead_tp_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/test_probe_write_user_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/trace_event_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/trace_output_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/tracex1_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/tracex2_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/tracex3_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/tracex4_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/tracex5_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/tracex6_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/tracex7_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/xdp_adjust_tail_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/xdp_fwd_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/xdp_monitor_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/xdp_redirect_cpu_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/xdp_redirect_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/xdp_redirect_map_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/xdp_router_ipv4_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/xdp_rxq_info_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/xdp_sample_pkts_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/xdp_tx_iptunnel_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/xdp1_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/xdp2_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/xdp2skb_meta_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/linux/xdpsock_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/new_linux/sock_flags_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/ovs/datapath.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/prototype-kernel/napi_monitor_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/prototype-kernel/tc_bench01_redirect_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/prototype-kernel/xdp_bench01_mem_access_cost_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/prototype-kernel/xdp_bench02_drop_pattern_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/prototype-kernel/xdp_ddos01_blacklist_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/prototype-kernel/xdp_monitor_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/prototype-kernel/xdp_redirect_cpu_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/prototype-kernel/xdp_redirect_err_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/prototype-kernel/xdp_tcpdump_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/prototype-kernel/xdp_ttl_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/prototype-kernel/xdp_vlan01_kern.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/suricata/bypass_filter.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/suricata/filter.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/suricata/lb.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/suricata/vlan_filter.o")
TEST_UNMARSHAL_MARSHAL("ebpf-samples/suricata/xdp_filter.o")

// Incorrect handling of INST_CLS_JMP32
TEST_UNMARSHAL_MARSHAL_FAIL("ebpf-samples/cilium/bpf_xdp_dsr_linux.o")
TEST_UNMARSHAL_MARSHAL_FAIL("ebpf-samples/cilium/bpf_xdp_dsr_linux_v1.o")
TEST_UNMARSHAL_MARSHAL_FAIL("ebpf-samples/cilium/bpf_xdp_snat_linux.o")
TEST_UNMARSHAL_MARSHAL_FAIL("ebpf-samples/cilium/bpf_xdp_snat_linux_v1.o")
