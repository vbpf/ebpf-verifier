// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <catch2/catch_all.hpp>

#include "ebpf_verifier.hpp"

using namespace crab;

TEST_CASE("Trivial loop: middle", "[sanity][loop]") {
    cfg_t cfg;

    basic_block_t& entry = cfg.insert(label_t(0));
    basic_block_t& middle = cfg.insert(label_t(1));
    basic_block_t& exit = cfg.get_node(cfg.exit_label());

    entry.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{0}, .v = Imm{0}, .is64 = true});
    middle.insert(Bin{.op = Bin::Op::ADD, .dst = Reg{0}, .v = Imm{1}, .is64 = true});

    cfg.get_node(cfg.entry_label()) >> entry;
    entry >> middle;
    middle >> middle;
    middle >> exit;

    ebpf_verifier_options_t options{
        .check_termination=false
    };
    program_info info{
        .platform = &g_ebpf_platform_linux,
        .type = g_ebpf_platform_linux.get_program_type("unspec", "unspec")
    };
    bool pass = run_ebpf_analysis(std::cout, cfg, info, &options, nullptr);
    REQUIRE(pass);
}
