#include <variant>
#include <iostream>
#include <vector>
#include <assert.h>


#include "linux_ebpf.hpp"

#include "asm.hpp"

using std::vector;

static uint8_t op(Condition::Op op)  {
    switch (op) {
        case Condition::Op::EQ : return 0x1;
        case Condition::Op::GT : return 0x2;
        case Condition::Op::GE : return 0x3;
        case Condition::Op::SET: return 0x4;
        case Condition::Op::NSET: assert(false);
        case Condition::Op::NE : return 0x5;
        case Condition::Op::SGT: return 0x6;
        case Condition::Op::SGE: return 0x7;
        case Condition::Op::LT : return 0xa;
        case Condition::Op::LE : return 0xb;
        case Condition::Op::SLT: return 0xc;
        case Condition::Op::SLE: return 0xd;
    }
}

static uint8_t op(Bin::Op op) {
    switch (op) {
        case Bin::Op::ADD : return 0x0;
        case Bin::Op::SUB : return 0x1;
        case Bin::Op::MUL : return 0x2;
        case Bin::Op::DIV : return 0x3;
        case Bin::Op::OR  : return 0x4;
        case Bin::Op::AND : return 0x5;
        case Bin::Op::LSH : return 0x6;
        case Bin::Op::RSH : return 0x7;
        case Bin::Op::MOD : return 0x9;
        case Bin::Op::XOR : return 0xa;
        case Bin::Op::MOV : return 0xb;
        case Bin::Op::ARSH: return 0xc;
    }
}

static uint8_t imm(Un::Op op) {
    switch (op) {
        case Un::Op::NEG  : return 0;
        case Un::Op::LE16 : return 16;
        case Un::Op::LE32 : return 32;
        case Un::Op::LE64 : return 64;
    }
}

static uint8_t access_width(Width w)
{
    switch (w) {
        case Width::B : return EBPF_SIZE_B;
        case Width::H : return EBPF_SIZE_H;
        case Width::W : return EBPF_SIZE_W;
        case Width::DW: return EBPF_SIZE_DW;
    }
}

struct MarshalVisitor {
private:
    vector<ebpf_inst> makeLddw(Reg dst, bool isFd, int32_t imm, int32_t next_imm) {
        return {
            ebpf_inst {
                .opcode = static_cast<uint8_t>(EBPF_CLS_LD | access_width(Width::DW)),
                .dst = static_cast<uint8_t>(dst),
                .src = static_cast<uint8_t>(isFd ? 1 : 0),
                .offset = 0,
                .imm = imm
            }, 
            ebpf_inst{ .imm = next_imm }
        };
    }

public:

    std::function<auto(std::string)->int16_t> label_to_offset;

    vector<ebpf_inst> operator()(Undefined const& a) {
        assert(false);
    }

    vector<ebpf_inst> operator()(LoadMapFd const& b) {
        return makeLddw(b.dst, true, b.mapfd, 0);
    }

    vector<ebpf_inst> operator()(Bin const& b) {
        if (b.lddw) {
            assert(std::holds_alternative<Imm>(b.v));
            auto [imm, next_imm] = split(std::get<Imm>(b.v).v);
            return makeLddw(b.dst, false, imm, next_imm);
        }

        ebpf_inst res{
            .opcode = static_cast<uint8_t>((b.is64 ? EBPF_CLS_ALU64 :EBPF_CLS_ALU) | (op(b.op) << 4)),
            .dst = static_cast<uint8_t>(b.dst),
            .src = 0,
            .offset = 0,
            .imm = 0
        };
        std::visit(overloaded{
            [&](Reg right) { 
                res.opcode |= EBPF_SRC_REG;
                res.src = static_cast<uint8_t>(right); },
            [&](Imm right) { res.imm = right.v; }
        }, b.v);
        return { res };
    }

    vector<ebpf_inst> operator()(Un const& b) {
        if (b.op == Un::Op::NEG) {
            return { ebpf_inst{
                // FIX: should be EBPF_CLS_ALU / EBPF_CLS_ALU64
                .opcode = static_cast<uint8_t>(EBPF_CLS_ALU | 0x3 | (0x8 << 4)),
                .dst = static_cast<uint8_t>(b.dst),
                .imm = imm(b.op),
            } };
        } else {
            // must be LE
            uint8_t cls = static_cast<uint8_t>(b.op == Un::Op::LE64 ? EBPF_CLS_ALU64 : EBPF_CLS_ALU);
            return { ebpf_inst{
                .opcode = static_cast<uint8_t>(cls | 0x8 | (0xd << 4) ),
                .dst = static_cast<uint8_t>(b.dst),
                .imm = imm(b.op),
            } };
        }
    }

    vector<ebpf_inst> operator()(Call const& b) {
        return { 
            ebpf_inst{
                .opcode = static_cast<uint8_t>(EBPF_OP_CALL),
                .dst = 0,
                .src = 0,
                .offset = 0,
                .imm = b.func
            }
        };
    }

    vector<ebpf_inst> operator()(Exit const& b) {
        return { 
            ebpf_inst{
                .opcode = EBPF_OP_EXIT,
                .dst = 0,
                .src = 0,
                .offset = 0,
                .imm = 0
            }
        };
    }

    vector<ebpf_inst> operator()(Assume const& b) {
        throw std::invalid_argument("Cannot marshal assumptions");
    }

    vector<ebpf_inst> operator()(Jmp const& b) {
        if (b.cond) {
            ebpf_inst res{
                .opcode = static_cast<uint8_t>(EBPF_CLS_JMP | (op(b.cond->op) << 4)),
                .dst = static_cast<uint8_t>(b.cond->left),
                .offset = label_to_offset(b.target),
            };
            visit(overloaded{
                [&](Reg right) { 
                    res.opcode |= EBPF_SRC_REG;
                    res.src = static_cast<uint8_t>(right);
                },
                [&](Imm right) { res.imm = right.v; }
            }, b.cond->right);
            return { res };
        } else {
            return { 
                ebpf_inst{
                    .opcode = EBPF_OP_JA,
                    .dst = 0,
                    .src = 0,
                    .offset = label_to_offset(b.target),
                    .imm = 0
                }
            };
        }
    }

    vector<ebpf_inst> operator()(Mem const& b) {
        ebpf_inst res{
            .opcode = static_cast<uint8_t>((EBPF_MEM << 5) | access_width(b.width)),
            .offset = static_cast<int16_t>(b.offset),
        };
        visit(overloaded{
            [&](Mem::Load reg) {
                res.opcode |= EBPF_CLS_LD | 0x1;
                res.dst = static_cast<uint8_t>(reg);
                res.src = static_cast<uint8_t>(b.basereg);
            },
            [&](Mem::StoreReg reg) {
                res.opcode |= EBPF_CLS_ST | 0x1;
                res.dst = static_cast<uint8_t>(b.basereg);
                res.src = static_cast<uint8_t>(reg);
            },
            [&](Mem::StoreImm imm) {
                res.opcode |= EBPF_CLS_ST | 0x0;
                res.dst = static_cast<uint8_t>(b.basereg),
                res.imm = imm;
            }
        }, b.value);
        return { res };
    }

    vector<ebpf_inst> operator()(Packet const& b) {
        ebpf_inst res{
            .opcode = static_cast<uint8_t>(EBPF_CLS_LD | access_width(b.width)),
            .imm = static_cast<int32_t>(b.offset),
        };
        if (b.regoffset) {
            res.opcode |= (EBPF_IND << 5);
            res.src = static_cast<uint8_t>(*b.regoffset);
        } else {
            res.opcode |= (EBPF_ABS << 5);
        }
        return { res };
    }

    vector<ebpf_inst> operator()(LockAdd const& b) {
        return { 
            ebpf_inst{
                .opcode = static_cast<uint8_t>(EBPF_CLS_ST | 0x1 | (EBPF_XADD << 5) | access_width(b.width)),
                .dst = static_cast<uint8_t>(b.basereg),
                .src = static_cast<uint8_t>(b.valreg),
                .offset = static_cast<int16_t>(b.offset),
                .imm = 0
            }
        };
    }
};

vector<ebpf_inst> marshal(Instruction ins, pc_t pc) {
    return std::visit(MarshalVisitor{label_to_offset(pc)}, ins);
}

vector<ebpf_inst> marshal(vector<Instruction> insts) {
    vector<ebpf_inst> res;
    pc_t pc = 0;
    for (auto ins : insts) {
        for (auto e: marshal(ins, pc)) {
            pc++;
            res.push_back(e);
        }
    }
    return res;
}