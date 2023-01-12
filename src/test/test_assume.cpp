// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <catch2/catch_all.hpp>

#include "crab/ebpf_domain.hpp"

using namespace crab;
using namespace asm_syntax;

TEST_CASE("Assume LT", "[assume]") {
    ebpf_domain_t left;
    left(Bin{.op = Bin::Op::MOV, .dst = Reg{0}, .v = Imm{0}, .is64 = true});

    ebpf_domain_t right;
    right(Bin{.op = Bin::Op::MOV, .dst = Reg{0}, .v = Imm{2}, .is64 = true});

    ebpf_domain_t joined = left | right;

    REQUIRE(joined.to_set() == string_invariant{{
        "r0.value=[0, 2]",
        "r0.type=number",
    }});

    joined(Assume{Condition{.op = Condition::Op::LT, .left = Reg{0}, .right = Imm{2}}});
    REQUIRE(!joined.is_bottom());
    REQUIRE(joined.to_set() == string_invariant{{
        "r0.value=[0, 1]",
        "r0.type=number",
    }});
}

TEST_CASE("Assume LE", "[assume]") {
    ebpf_domain_t left;
    left(Bin{.op = Bin::Op::MOV, .dst = Reg{0}, .v = Imm{0}, .is64 = true});

    ebpf_domain_t right;
    right(Bin{.op = Bin::Op::MOV, .dst = Reg{0}, .v = Imm{2}, .is64 = true});

    ebpf_domain_t joined = left | right;

    REQUIRE(joined.to_set() == string_invariant{{
        "r0.value=[0, 2]",
        "r0.type=number",
    }});

    joined(Assume{Condition{.op = Condition::Op::LE, .left = Reg{0}, .right = Imm{1}}});
    REQUIRE(!joined.is_bottom());
    REQUIRE(joined.to_set() == string_invariant{{
        "r0.value=[0, 1]",
        "r0.type=number",
    }});
}
