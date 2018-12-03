#include "catch.hpp"
#include "asm.hpp"
#include <cstring>

static void compare_marshal_unmarshal(const Instruction& ins, bool double_cmd = false) {
    std::vector<Instruction> parsed = parse(marshal(ins, 0));
    if (double_cmd) {
        REQUIRE(parsed.size() == 2);
        REQUIRE(std::holds_alternative<Undefined>(parsed.back()));
        parsed.pop_back();
    } else {
        REQUIRE(parsed.size() == 1);
    }
    Instruction single = parsed.back();
    REQUIRE(single == ins);
}

TEST_CASE( "disasm_marshal", "[disasm][marshal]" ) {
    SECTION( "Bin" ) {
        auto ops = {
            Bin::Op::MOV,
            Bin::Op::ADD,
            Bin::Op::SUB,
            Bin::Op::MUL,
            Bin::Op::DIV,
            Bin::Op::MOD,
            Bin::Op::OR,
            Bin::Op::AND,
            Bin::Op::LSH,
            Bin::Op::RSH,
            Bin::Op::ARSH,
            Bin::Op::XOR 
        };
        SECTION( "Reg src" ) {
            for (auto op : ops) {
                compare_marshal_unmarshal(Bin{.op = op, .is64 = true, .dst = Reg{ 1 }, .v = Reg{ 2 } });
                compare_marshal_unmarshal(Bin{.op = op, .is64 = false, .dst = Reg{ 1 }, .v = Reg{ 2 } });
            }
        }
        SECTION( "Imm src" ) {
            for (auto op : ops) {
                // .is64=true should fail?
                compare_marshal_unmarshal(Bin{.op = op, .is64 = false, .dst = Reg{ 1 }, .v = Imm{ 2 } });
                compare_marshal_unmarshal(Bin{.op = op, .is64 = true, .dst = Reg{ 1 }, .v = Imm{ 2 } });
            }
            SECTION( "LDDW" ) {
                compare_marshal_unmarshal(Bin{.op = Bin::Op::MOV, .is64 = true, .dst = Reg{ 1 }, .v = Imm{ 2 },
                    .lddw=true }, true);
            }
        }
    }

    SECTION( "Un" ) {
        auto ops = {
            Un::Op::LE16,
            Un::Op::LE32,
            Un::Op::LE64,
            Un::Op::NEG,
        };
        for (auto op : ops)
            compare_marshal_unmarshal(Un{.op = op, .dst = Reg{ 1 } });
    }

    SECTION( "LoadMapFd" ) {
        compare_marshal_unmarshal(LoadMapFd{ .dst = Reg{ 1 }, .mapfd = 1 }, true);
    }

    SECTION( "Jmp" ) {
        auto ops = {
            Condition::Op::EQ,
            Condition::Op::GT,
            Condition::Op::GE,
            Condition::Op::SET,
            // Condition::Op::NSET, does not exist in ebpf
            Condition::Op::NE,
            Condition::Op::SGT,
            Condition::Op::SGE,
            Condition::Op::LT,
            Condition::Op::LE,
            Condition::Op::SLT,
            Condition::Op::SLE
        };
        SECTION( "Reg right" ) {
            for (auto op : ops) {
                Condition cond{ .op = op, .left = Reg{1}, .right = Reg{2} };
                compare_marshal_unmarshal(Jmp{.cond = cond, .target = "1" });
            }
        }
        SECTION( "Imm right" ) {
            for (auto op : ops) {
                Condition cond{ .op = op, .left = Reg{1}, .right = Imm{2} };
                compare_marshal_unmarshal(Jmp{.cond = cond, .target = "1" });
            }
        }
    }

    SECTION( "Call" ) {
        for (int func : {1, 17})
            compare_marshal_unmarshal(Call{func});
    }

    SECTION( "Exit" ) {
        compare_marshal_unmarshal(Exit{});
    }
    
    const auto ws = {Width::B, Width::H, Width::W, Width::DW};
    SECTION( "Mem" ) {
        Deref access{ .basereg = Reg{1}, .offset = 7 };
        SECTION( "Load" ) {
            for (Width w : ws) {
                access.width = w;
                compare_marshal_unmarshal(Mem{access, .value = Reg{ 3 }, ._is_load=true });
            }
        }
        SECTION( "Store Register" ) {
            for (Width w : ws) {
                access.width = w;
                compare_marshal_unmarshal(Mem{access, .value = Reg{ 4 }, ._is_load=false });
            }
        }
        SECTION( "Store Immediate" ) {
            for (Width w : ws) {
                access.width = w;
                compare_marshal_unmarshal(Mem{access, .value = Imm{ 5 }, ._is_load=false });
            }
        }
        
    }

    SECTION( "Packet" ) {
        for (Width w : ws) {
            compare_marshal_unmarshal(Packet{.width = w, .offset = 7, .regoffset = {}});
            compare_marshal_unmarshal(Packet{.width = w, .offset = 7, .regoffset = Reg{ 2 }});
        }
    }

    SECTION( "LockAdd" ) {
        for (Width w : {Width::B, Width::H, Width::W, Width::DW}) {
            Deref access{ .width = w, .basereg = Reg{2}, .offset = 17 };
            compare_marshal_unmarshal(LockAdd{access, .valreg = Reg{ 1 }});
        }
    }
}
