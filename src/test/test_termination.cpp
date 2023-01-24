// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <catch2/catch_all.hpp>

#include "crab/cfg.hpp"
#include "crab_verifier.hpp"
#include "config.hpp"
#include "platform.hpp"

using namespace crab;

TEST_CASE("Trivial infinite loop", "[loop][termination]") {
    cfg_t cfg;

    basic_block_t& entry = cfg.get_node(cfg.entry_label());
    basic_block_t& middle = cfg.insert(label_t(0));
    basic_block_t& exit = cfg.get_node(cfg.exit_label());

    entry >> middle;
    middle >> middle;
    middle >> exit;

    ebpf_verifier_options_t options{
        .check_termination = true,
    };
    program_info info{
        .platform = &g_ebpf_platform_linux,
        .type = g_ebpf_platform_linux.get_program_type("unspec", "unspec")
    };
    ebpf_verifier_stats_t stats;
    bool pass = run_ebpf_analysis(std::cout, cfg, info, &options, &stats);
    REQUIRE_FALSE(pass);
    REQUIRE(stats.max_instruction_count == INT_MAX);
    REQUIRE(stats.total_unreachable == 0);
    REQUIRE(stats.total_warnings == 1);
}

TEST_CASE("Trivial finite loop", "[loop][termination]") {
    cfg_t cfg;

    basic_block_t& entry = cfg.get_node(cfg.entry_label());
    basic_block_t& start = cfg.insert(label_t(0));
    basic_block_t& middle = cfg.insert(label_t(1));
    basic_block_t& exit = cfg.get_node(cfg.exit_label());

    Reg r{0};
    start.insert(Bin{.op = Bin::Op::MOV, .dst = r, .v = Imm{0}, .is64 = true});
    middle.insert(Assume{{.op=Condition::Op::GT, .left=r, .right=Imm{10}, .is64=true}});
    middle.insert(Bin{.op = Bin::Op::ADD, .dst = r, .v = Imm{1}, .is64 = true});

    entry >> start;
    start >> middle;
    middle >> middle;
    middle >> exit;

    ebpf_verifier_options_t options{
        .check_termination = true,
    };
    program_info info{
        .platform = &g_ebpf_platform_linux,
        .type = g_ebpf_platform_linux.get_program_type("unspec", "unspec")
    };
    ebpf_verifier_stats_t stats;
    bool pass = run_ebpf_analysis(std::cout, cfg, info, &options, &stats);
    REQUIRE(pass);
    REQUIRE(stats.max_instruction_count == 3);
    REQUIRE(stats.total_unreachable == 1);
    REQUIRE(stats.total_warnings == 0);
}
