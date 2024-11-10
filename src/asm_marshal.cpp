// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <cassert>
#include <map>
#include <variant>
#include <vector>

#include "asm_marshal.hpp"
#include "crab_utils/num_safety.hpp"

using std::vector;

static uint8_t op(const Condition::Op op) {
    using Op = Condition::Op;
    switch (op) {
    case Op::EQ: return 0x1;
    case Op::GT: return 0x2;
    case Op::GE: return 0x3;
    case Op::SET: return 0x4;
    case Op::NSET: assert(false);
    case Op::NE: return 0x5;
    case Op::SGT: return 0x6;
    case Op::SGE: return 0x7;
    case Op::LT: return 0xa;
    case Op::LE: return 0xb;
    case Op::SLT: return 0xc;
    case Op::SLE: return 0xd;
    }
    assert(false);
    return {};
}

static uint8_t op(const Bin::Op op) {
    using Op = Bin::Op;
    switch (op) {
    case Op::ADD: return 0x0;
    case Op::SUB: return 0x1;
    case Op::MUL: return 0x2;
    case Op::SDIV:
    case Op::UDIV: return 0x3;
    case Op::OR: return 0x4;
    case Op::AND: return 0x5;
    case Op::LSH: return 0x6;
    case Op::RSH: return 0x7;
    case Op::SMOD:
    case Op::UMOD: return 0x9;
    case Op::XOR: return 0xa;
    case Op::MOV:
    case Op::MOVSX8:
    case Op::MOVSX16:
    case Op::MOVSX32: return 0xb;
    case Op::ARSH: return 0xc;
    }
    assert(false);
    return {};
}

static int16_t offset(const Bin::Op op) {
    using Op = Bin::Op;
    switch (op) {
    case Op::SDIV:
    case Op::SMOD: return 1;
    case Op::MOVSX8: return 8;
    case Op::MOVSX16: return 16;
    case Op::MOVSX32: return 32;
    default: return 0;
    }
}

static uint8_t imm_endian(const Un::Op op) {
    using Op = Un::Op;
    switch (op) {
    case Op::NEG: assert(false); return 0;
    case Op::BE16:
    case Op::LE16:
    case Op::SWAP16: return 16;
    case Op::BE32:
    case Op::LE32:
    case Op::SWAP32: return 32;
    case Op::BE64:
    case Op::LE64:
    case Op::SWAP64: return 64;
    }
    assert(false);
    return {};
}

struct MarshalVisitor {
  private:
    static vector<ebpf_inst> makeLddw(const Reg dst, const bool isFd, const int32_t imm, const int32_t next_imm) {
        return {ebpf_inst{.opcode = gsl::narrow<uint8_t>(INST_CLS_LD | width_to_opcode(8)),
                          .dst = dst.v,
                          .src = gsl::narrow<uint8_t>(isFd ? 1 : 0),
                          .offset = 0,
                          .imm = imm},
                ebpf_inst{.opcode = 0, .dst = 0, .src = 0, .offset = 0, .imm = next_imm}};
    }

  public:
    std::function<auto(label_t)->int16_t> label_to_offset16;
    std::function<auto(label_t)->int32_t> label_to_offset32;

    vector<ebpf_inst> operator()(Undefined const& a) const {
        assert(false);
        return {};
    }

    vector<ebpf_inst> operator()(LoadMapFd const& b) const { return makeLddw(b.dst, true, b.mapfd, 0); }

    vector<ebpf_inst> operator()(Bin const& b) const {
        if (b.lddw) {
            const auto pimm = std::get_if<Imm>(&b.v);
            assert(pimm != nullptr);
            auto [imm, next_imm] = split(pimm->v);
            return makeLddw(b.dst, false, imm, next_imm);
        }

        ebpf_inst res{.opcode = gsl::narrow<uint8_t>((b.is64 ? INST_CLS_ALU64 : INST_CLS_ALU) | (op(b.op) << 4)),
                      .dst = b.dst.v,
                      .src = 0,
                      .offset = offset(b.op),
                      .imm = 0};
        std::visit(overloaded{[&](const Reg right) {
                                  res.opcode |= INST_SRC_REG;
                                  res.src = right.v;
                              },
                              [&](const Imm right) { res.imm = gsl::narrow<int32_t>(right.v); }},
                   b.v);
        return {res};
    }

    vector<ebpf_inst> operator()(Un const& b) const {
        switch (b.op) {
        case Un::Op::NEG:
            return {ebpf_inst{
                .opcode = gsl::narrow<uint8_t>((b.is64 ? INST_CLS_ALU64 : INST_CLS_ALU) | INST_ALU_OP_NEG),
                .dst = b.dst.v,
                .src = 0,
                .offset = 0,
                .imm = 0,
            }};
        case Un::Op::LE16:
        case Un::Op::LE32:
        case Un::Op::LE64:
            return {ebpf_inst{
                .opcode = gsl::narrow<uint8_t>(INST_CLS_ALU | INST_END_LE | INST_ALU_OP_END),
                .dst = b.dst.v,
                .src = 0,
                .offset = 0,
                .imm = imm_endian(b.op),
            }};
        case Un::Op::BE16:
        case Un::Op::BE32:
        case Un::Op::BE64:
            return {ebpf_inst{
                .opcode = gsl::narrow<uint8_t>(INST_CLS_ALU | INST_END_BE | INST_ALU_OP_END),
                .dst = b.dst.v,
                .src = 0,
                .offset = 0,
                .imm = imm_endian(b.op),
            }};
        case Un::Op::SWAP16:
        case Un::Op::SWAP32:
        case Un::Op::SWAP64:
            return {ebpf_inst{
                .opcode = gsl::narrow<uint8_t>(INST_CLS_ALU64 | INST_ALU_OP_END),
                .dst = b.dst.v,
                .src = 0,
                .offset = 0,
                .imm = imm_endian(b.op),
            }};
        }
        assert(false);
        return {};
    }

    vector<ebpf_inst> operator()(Call const& b) const {
        return {ebpf_inst{.opcode = gsl::narrow<uint8_t>(INST_OP_CALL),
                          .dst = 0,
                          .src = INST_CALL_STATIC_HELPER,
                          .offset = 0,
                          .imm = b.func}};
    }

    vector<ebpf_inst> operator()(CallLocal const& b) const {
        return {ebpf_inst{.opcode = gsl::narrow<uint8_t>(INST_OP_CALL),
                          .dst = 0,
                          .src = INST_CALL_LOCAL,
                          .offset = 0,
                          .imm = label_to_offset32(b.target)}};
    }

    vector<ebpf_inst> operator()(Callx const& b) const {
        // callx is defined to have the register in 'dst' not in 'src'.
        return {ebpf_inst{.opcode = gsl::narrow<uint8_t>(INST_OP_CALLX),
                          .dst = b.func.v,
                          .src = INST_CALL_STATIC_HELPER,
                          .offset = 0}};
    }

    vector<ebpf_inst> operator()(Exit const& b) const {
        return {ebpf_inst{.opcode = INST_OP_EXIT, .dst = 0, .src = 0, .offset = 0, .imm = 0}};
    }

    vector<ebpf_inst> operator()(Assume const&) const { throw std::invalid_argument("Cannot marshal assumptions"); }

    vector<ebpf_inst> operator()(Jmp const& b) const {
        if (b.cond) {
            ebpf_inst res{
                .opcode = gsl::narrow<uint8_t>(INST_CLS_JMP | (op(b.cond->op) << 4)),
                .dst = b.cond->left.v,
                .src = 0,
                .offset = label_to_offset16(b.target),
            };
            visit(overloaded{[&](const Reg right) {
                                 res.opcode |= INST_SRC_REG;
                                 res.src = right.v;
                             },
                             [&](const Imm right) { res.imm = gsl::narrow<int32_t>(right.v); }},
                  b.cond->right);
            return {res};
        } else {
            const int32_t imm = label_to_offset32(b.target);
            if (imm != 0) {
                return {ebpf_inst{.opcode = INST_OP_JA32, .imm = imm}};
            } else {
                return {ebpf_inst{.opcode = INST_OP_JA16, .offset = label_to_offset16(b.target)}};
            }
        }
    }

    vector<ebpf_inst> operator()(Mem const& b) const {
        const Deref access = b.access;
        ebpf_inst res{
            .opcode = gsl::narrow<uint8_t>(INST_MODE_MEM | width_to_opcode(access.width)),
            .dst = 0,
            .src = 0,
            .offset = gsl::narrow<int16_t>(access.offset),
        };
        if (b.is_load) {
            if (!std::holds_alternative<Reg>(b.value)) {
                throw std::runtime_error(std::string("LD IMM: ") + to_string(b));
            }
            res.opcode |= INST_CLS_LD | 0x1;
            res.dst = gsl::narrow<uint8_t>(std::get<Reg>(b.value).v);
            res.src = access.basereg.v;
        } else {
            res.opcode |= INST_CLS_ST;
            res.dst = access.basereg.v;
            if (const auto preg = std::get_if<Reg>(&b.value)) {
                res.opcode |= 0x1;
                res.src = preg->v;
            } else {
                res.opcode |= 0x0;
                res.imm = gsl::narrow<int32_t>(std::get<Imm>(b.value).v);
            }
        }
        return {res};
    }

    vector<ebpf_inst> operator()(Packet const& b) const {
        ebpf_inst res{
            .opcode = gsl::narrow<uint8_t>(INST_CLS_LD | width_to_opcode(b.width)),
            .dst = 0,
            .src = 0,
            .offset = 0,
            .imm = gsl::narrow<int32_t>(b.offset),
        };
        if (b.regoffset) {
            res.opcode |= INST_MODE_IND;
            res.src = b.regoffset->v;
        } else {
            res.opcode |= INST_MODE_ABS;
        }
        return {res};
    }

    vector<ebpf_inst> operator()(Atomic const& b) const {
        auto imm = gsl::narrow<int32_t>(b.op);
        if (b.fetch) {
            imm |= INST_FETCH;
        }
        return {
            ebpf_inst{.opcode = gsl::narrow<uint8_t>(INST_CLS_STX | INST_MODE_ATOMIC | width_to_opcode(b.access.width)),
                      .dst = b.access.basereg.v,
                      .src = b.valreg.v,
                      .offset = gsl::narrow<int16_t>(b.access.offset),
                      .imm = imm}};
    }

    vector<ebpf_inst> operator()(IncrementLoopCounter const&) const { return {}; }
};

vector<ebpf_inst> marshal(const Instruction& ins, const pc_t pc) {
    return std::visit(MarshalVisitor{crab::label_to_offset16(pc), crab::label_to_offset32(pc)}, ins);
}

static int size(const Instruction& inst) {
    if (const auto pins = std::get_if<Bin>(&inst)) {
        if (pins->lddw) {
            return 2;
        }
    }
    if (std::holds_alternative<LoadMapFd>(inst)) {
        return 2;
    }
    return 1;
}

static auto get_labels(const InstructionSeq& insts) {
    pc_t pc = 0;
    std::map<label_t, pc_t> pc_of_label;
    for (const auto& [label, inst, _] : insts) {
        pc_of_label[label] = pc;
        pc += size(inst);
    }
    return pc_of_label;
}

vector<ebpf_inst> marshal(const InstructionSeq& insts) {
    vector<ebpf_inst> res;
    const auto pc_of_label = get_labels(insts);
    pc_t pc = 0;
    for (auto [label, ins, _] : insts) {
        (void)label; // unused
        if (const auto pins = std::get_if<Jmp>(&ins)) {
            pins->target = label_t{gsl::narrow<int>(pc_of_label.at(pins->target))};
        }
        for (const auto e : marshal(ins, pc)) {
            pc++;
            res.push_back(e);
        }
    }
    return res;
}
