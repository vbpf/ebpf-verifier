// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "catch.hpp"

#include "crab/cfg.hpp"
#include "crab_verifier.hpp"
#include "config.hpp"

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
    bool pass = run_ebpf_analysis(std::cout, cfg, {}, &options);
    REQUIRE_FALSE(pass);
}

TEST_CASE("Trivial finite loop", "[loop][termination]") {
    cfg_t cfg;

    basic_block_t& entry = cfg.get_node(cfg.entry_label());
    basic_block_t& start = cfg.insert(label_t(0));
    basic_block_t& middle = cfg.insert(label_t(1));
    basic_block_t& exit = cfg.get_node(cfg.exit_label());

    Reg r{0};
    start.insert(Bin{.op = Bin::Op::MOV, .dst = r, .v = Imm{0}, .is64 = true});
    middle.insert(Assume{{.op=Condition::Op::GT, .left=r, .right=Imm{10}}});
    middle.insert(Bin{.op = Bin::Op::ADD, .dst = r, .v = Imm{1}, .is64 = true});

    entry >> start;
    start >> middle;
    middle >> middle;
    middle >> exit;

    ebpf_verifier_options_t options{
        .check_termination = true,
    };
    bool pass = run_ebpf_analysis(std::cout, cfg, {}, &options);
    REQUIRE(pass);
}
