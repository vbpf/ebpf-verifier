// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "catch.hpp"

#include "crab/cfg.hpp"
#include "crab_verifier.hpp"
#include "config.hpp"

using namespace crab;

constexpr Bin NOP = Bin{.op = Bin::Op::MOV, .dst = Reg{1}, .v = Reg{1}};

TEST_CASE("Trivial loop: middle", "[sanity][loop]") {
    cfg_t cfg;

    basic_block_t& entry = cfg.get_node(cfg.entry_label());
    basic_block_t& middle = cfg.insert(label_t(1));
    basic_block_t& exit = cfg.get_node(cfg.exit_label());

    entry.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{0}, .v = Imm{0}, .is64 = true});
    middle.insert(Bin{.op = Bin::Op::ADD, .dst = Reg{0}, .v = Imm{1}, .is64 = true});

    entry >> middle;
    middle >> middle;
    middle >> exit;

    auto [pass, time] = run_ebpf_analysis(cfg, {});
    REQUIRE(pass);
}
