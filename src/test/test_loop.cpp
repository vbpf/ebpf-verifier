// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "catch.hpp"

#include "crab/cfg.hpp"
#include "crab_verifier.hpp"
#include "config.hpp"

using namespace crab;

constexpr Bin NOP = Bin{.op = Bin::Op::MOV, .dst = Reg{1}, .v = Reg{1}};

TEST_CASE("Trivial loop: entry <-> exit", "[sanity][loop]") {
    cfg_t cfg(label_t(0), label_t(2));

    basic_block_t& entry = cfg.get_node(cfg.entry());
    basic_block_t& exit = cfg.get_node(cfg.exit());

    entry.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{0}, .v = Imm{0}, .is64 = true});
    exit.insert(Bin{.op = Bin::Op::ADD, .dst = Reg{0}, .v = Imm{1}, .is64 = true});

    entry >> exit;
    exit >> exit;

    auto [pass, time] = run_ebpf_analysis(cfg, {});
    REQUIRE(pass);
}

TEST_CASE("Trivial loop: middle", "[sanity][loop]") {
    cfg_t cfg(label_t(0), label_t(2));

    basic_block_t& entry = cfg.get_node(cfg.entry());
    basic_block_t& middle = cfg.insert(label_t(1));
    basic_block_t& exit = cfg.get_node(cfg.exit());

    entry.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{0}, .v = Imm{0}, .is64 = true});
    middle.insert(Bin{.op = Bin::Op::ADD, .dst = Reg{0}, .v = Imm{1}, .is64 = true});

    entry >> middle;
    middle >> middle;
    middle >> exit;

    auto [pass, time] = run_ebpf_analysis(cfg, {});
    REQUIRE(pass);
}

TEST_CASE("Trivial loop: entry -> middle <-> exit", "[sanity][loop]") {
    cfg_t cfg(label_t(0), label_t(2));

    basic_block_t& entry = cfg.get_node(cfg.entry());
    basic_block_t& middle = cfg.insert(label_t(1));
    basic_block_t& exit = cfg.get_node(cfg.exit());

    entry.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{0}, .v = Imm{0}, .is64 = true});
    middle.insert(Bin{.op = Bin::Op::ADD, .dst = Reg{0}, .v = Imm{1}, .is64 = true});

    entry >> middle;
    middle >> exit;
    exit >> middle;

    auto [pass, time] = run_ebpf_analysis(cfg, {});
    REQUIRE(pass);
}
