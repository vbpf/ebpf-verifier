// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <cassert>
#include <iostream>
#include <string>
#include <vector>

#include "ebpf_vm_isa.hpp"

#include "asm_unmarshal.hpp"

using std::string;
using std::vector;

int opcode_to_width(uint8_t opcode) {
    switch (opcode & INST_SIZE_MASK) {
    case INST_SIZE_B: return 1;
    case INST_SIZE_H: return 2;
    case INST_SIZE_W: return 4;
    case INST_SIZE_DW: return 8;
    }
    assert(false);
    return {};
}

uint8_t width_to_opcode(int width) {
    switch (width) {
    case 1: return INST_SIZE_B;
    case 2: return INST_SIZE_H;
    case 4: return INST_SIZE_W;
    case 8: return INST_SIZE_DW;
    }
    assert(false);
    return {};
}

template <typename T>
void compare(const string& field, T actual, T expected) {
    if (actual != expected)
        std::cerr << field << ": (actual) " << std::hex << (int)actual << " != " << (int)expected << " (expected)\n";
}

struct InvalidInstruction : std::invalid_argument {
    size_t pc;
    explicit InvalidInstruction(size_t pc, const char* what) : std::invalid_argument{what}, pc{pc} {}
};

struct UnsupportedMemoryMode : std::invalid_argument {
    explicit UnsupportedMemoryMode(const char* what) : std::invalid_argument{what} {}
};

static auto getMemIsLoad(uint8_t opcode) -> bool {
    switch (opcode & INST_CLS_MASK) {
    case INST_CLS_LD:
    case INST_CLS_LDX: return true;
    case INST_CLS_ST:
    case INST_CLS_STX: return false;
    }
    return {};
}

static auto getMemWidth(uint8_t opcode) -> int {
    switch (opcode & INST_SIZE_MASK) {
    case INST_SIZE_B: return 1;
    case INST_SIZE_H: return 2;
    case INST_SIZE_W: return 4;
    case INST_SIZE_DW: return 8;
    }
    return {};
}

// static auto getMemX(uint8_t opcode) -> bool {
//     switch (opcode & INST_CLS_MASK) {
//         case INST_CLS_LD : return false;
//         case INST_CLS_ST : return false;
//         case INST_CLS_LDX: return true;
//         case INST_CLS_STX: return true;
//     }
//     return {};
// }

struct Unmarshaller {
    vector<vector<string>>& notes;
    const program_info& info;
    void note(const string& what) { notes.back().emplace_back(what); }
    void note_next_pc() { notes.emplace_back(); }
    explicit Unmarshaller(vector<vector<string>>& notes, const program_info& info) : notes{notes}, info{info} { note_next_pc(); }

    auto getAluOp(size_t pc, ebpf_inst inst) -> std::variant<Bin::Op, Un::Op> {
        switch (inst.opcode & INST_ALU_OP_MASK) {
        case INST_ALU_OP_ADD: return Bin::Op::ADD;
        case INST_ALU_OP_SUB: return Bin::Op::SUB;
        case INST_ALU_OP_MUL: return Bin::Op::MUL;
        case INST_ALU_OP_DIV: return Bin::Op::UDIV;
        case INST_ALU_OP_OR: return Bin::Op::OR;
        case INST_ALU_OP_AND: return Bin::Op::AND;
        case INST_ALU_OP_LSH: return Bin::Op::LSH;
        case INST_ALU_OP_RSH: return Bin::Op::RSH;
        case INST_ALU_OP_NEG: return Un::Op::NEG;
        case INST_ALU_OP_MOD: return Bin::Op::UMOD;
        case INST_ALU_OP_XOR: return Bin::Op::XOR;
        case INST_ALU_OP_MOV: return Bin::Op::MOV;
        case INST_ALU_OP_ARSH:
            if ((inst.opcode & INST_CLS_MASK) == INST_CLS_ALU)
                note("arsh32 is not allowed");
            return Bin::Op::ARSH;
        case INST_ALU_OP_END:
            switch (inst.imm) {
            case 16: return (inst.opcode & INST_END_BE) ? Un::Op::BE16 : Un::Op::LE16;
            case 32:
                if ((inst.opcode & INST_CLS_MASK) == INST_CLS_ALU64)
                    throw InvalidInstruction(pc, "invalid endian immediate 32 for 64 bit instruction");
                return (inst.opcode & INST_END_BE) ? Un::Op::BE32 : Un::Op::LE32;
            case 64:
                return (inst.opcode & INST_END_BE) ? Un::Op::BE64 : Un::Op::LE64;
            default:
                throw InvalidInstruction(pc, "invalid endian immediate");
            }
        case 0xe0: throw InvalidInstruction{pc, "invalid ALU op 0xe0"};
        case 0xf0: throw InvalidInstruction{pc, "invalid ALU op 0xf0"};
        }
        return {};
    }

    uint64_t sign_extend(int32_t imm) { return (uint64_t)(int64_t)imm; }

    uint64_t zero_extend(int32_t imm) { return (uint64_t)(uint32_t)imm; }

    auto getBinValue(pc_t pc, ebpf_inst inst) -> Value {
        if (inst.offset != 0)
            throw InvalidInstruction{pc, "nonzero offset for register alu op"};
        if (inst.opcode & INST_SRC_REG) {
            if (inst.imm != 0)
                throw InvalidInstruction{pc, "nonzero imm for register alu op"};
            return Reg{inst.src};
        } else {
            if (inst.src != 0)
                throw InvalidInstruction{pc, "nonzero src for register alu op"};
            // Imm is a signed 32-bit number.  Sign extend it to 64-bits for storage.
            return Imm{sign_extend(inst.imm)};
        }
    }

    static auto getJmpOp(size_t pc, uint8_t opcode) -> Condition::Op {
        using Op = Condition::Op;
        switch ((opcode >> 4) & 0xF) {
        case 0x0: return {}; // goto
        case 0x1: return Op::EQ;
        case 0x2: return Op::GT;
        case 0x3: return Op::GE;
        case 0x4: return Op::SET;
        case 0x5: return Op::NE;
        case 0x6: return Op::SGT;
        case 0x7: return Op::SGE;
        case 0x8: return {}; // call
        case 0x9: return {}; // exit
        case 0xa: return Op::LT;
        case 0xb: return Op::LE;
        case 0xc: return Op::SLT;
        case 0xd: return Op::SLE;
        case 0xe: throw InvalidInstruction(pc, "invalid JMP op 0xe");
        }
        return {};
    }

    auto makeMemOp(pc_t pc, ebpf_inst inst) -> Instruction {
        if (inst.dst > R10_STACK_POINTER || inst.src > R10_STACK_POINTER)
            throw InvalidInstruction(pc, "Bad register");

        int width = getMemWidth(inst.opcode);
        bool isLD = (inst.opcode & INST_CLS_MASK) == INST_CLS_LD;
        switch ((inst.opcode & INST_MODE_MASK) >> 5) {
        case 0:
            throw InvalidInstruction(pc, "Bad instruction");
        case INST_ABS:
            if (!isLD)
                throw InvalidInstruction(pc, "ABS but not LD");
            if (width == 8)
                note("invalid opcode LDABSDW");
            return Packet{.width = width, .offset = inst.imm, .regoffset = {}};

        case INST_IND:
            if (!isLD)
                throw InvalidInstruction(pc, "IND but not LD");
            if (width == 8)
                note("invalid opcode LDINDDW");
            return Packet{.width = width, .offset = inst.imm, .regoffset = Reg{inst.src}};

        case INST_MEM: {
            if (isLD)
                throw InvalidInstruction(pc, "plain LD");
            bool isLoad = getMemIsLoad(inst.opcode);
            if (isLoad && inst.dst == R10_STACK_POINTER)
                throw InvalidInstruction(pc, "Cannot modify r10");
            bool isImm = !(inst.opcode & 1);

            assert(!(isLoad && isImm));
            uint8_t basereg = isLoad ? inst.src : inst.dst;

            if (basereg == R10_STACK_POINTER && (inst.offset + opcode_to_width(inst.opcode) > 0 || inst.offset < -EBPF_STACK_SIZE)) {
                note("Stack access out of bounds");
            }
            auto res = Mem{
                .access =
                    Deref{
                        .width = width,
                        .basereg = Reg{basereg},
                        .offset = inst.offset,
                    },
                .value =
                    isLoad ? (Value)Reg{inst.dst} : (isImm ? (Value)Imm{zero_extend(inst.imm)} : (Value)Reg{inst.src}),
                .is_load = isLoad,
            };
            return res;
        }

        case INST_XADD:
            if (((inst.opcode & INST_CLS_MASK) != INST_CLS_STX) ||
                ((inst.opcode & INST_SIZE_MASK) != INST_SIZE_W &&
                 (inst.opcode & INST_SIZE_MASK) != INST_SIZE_DW))
                throw InvalidInstruction(pc, "Bad instruction");
            if (inst.imm != 0)
                throw InvalidInstruction(pc, "Unsupported atomic instruction");
            return LockAdd{
                .access =
                    Deref{
                        .width = width,
                        .basereg = Reg{inst.dst},
                        .offset = inst.offset,
                    },
                .valreg = Reg{inst.src},
            };
        default:
            throw InvalidInstruction(pc, "Bad instruction");
        }
        return {};
    }

    auto makeAluOp(size_t pc, ebpf_inst inst) -> Instruction {
        if (inst.dst == R10_STACK_POINTER)
            throw InvalidInstruction(pc, "Invalid target r10");
        return std::visit(overloaded{[&](Un::Op op) -> Instruction { return Un{.op = op, .dst = Reg{inst.dst}, .is64 = (inst.opcode & INST_CLS_MASK) == INST_CLS_ALU64}; },
                                     [&](Bin::Op op) -> Instruction {
                                         Bin res{
                                             .op = op,
                                             .dst = Reg{inst.dst},
                                             .v = getBinValue(pc, inst),
                                             .is64 = (inst.opcode & INST_CLS_MASK) == INST_CLS_ALU64,
                                         };
                                         if (!thread_local_options.allow_division_by_zero && (op == Bin::Op::UDIV || op == Bin::Op::UMOD))
                                             if (std::holds_alternative<Imm>(res.v) && std::get<Imm>(res.v).v == 0)
                                                 note("division by zero");
                                         return res;
                                     }},
                          getAluOp(pc, inst));
    }

    auto makeLddw(ebpf_inst inst, int32_t next_imm, const vector<ebpf_inst>& insts, pc_t pc) -> Instruction {
        if (pc >= insts.size() - 1)
            throw InvalidInstruction(pc, "incomplete LDDW");
        if (inst.src > 1 || inst.dst > R10_STACK_POINTER || inst.offset != 0)
            throw InvalidInstruction(pc, "LDDW uses reserved fields");

        if (inst.src == 1) {
            // magic number, meaning we're a per-process file descriptor defining the map.
            // (for details, look for BPF_PSEUDO_MAP_FD in the kernel)

            return LoadMapFd{.dst = Reg{inst.dst}, .mapfd = inst.imm};
        }

        ebpf_inst next = insts[pc + 1];
        if (next.opcode != 0 || next.dst != 0 || next.src != 0 || next.offset != 0)
            throw InvalidInstruction(pc, "invalid LDDW");
        return Bin{
            .op = Bin::Op::MOV,
            .dst = Reg{inst.dst},
            .v = Imm{merge(inst.imm, next_imm)},
            .is64 = true,
            .lddw = true,
        };
    }

    static ArgSingle::Kind toArgSingleKind(ebpf_argument_type_t t) {
        switch (t) {
        case EBPF_ARGUMENT_TYPE_ANYTHING: return ArgSingle::Kind::ANYTHING;
        case EBPF_ARGUMENT_TYPE_PTR_TO_MAP: return ArgSingle::Kind::MAP_FD;
        case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_OF_PROGRAMS: return ArgSingle::Kind::MAP_FD_PROGRAMS;
        case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY: return ArgSingle::Kind::PTR_TO_MAP_KEY;
        case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE: return ArgSingle::Kind::PTR_TO_MAP_VALUE;
        case EBPF_ARGUMENT_TYPE_PTR_TO_CTX: return ArgSingle::Kind::PTR_TO_CTX;
        default: break;
        }
        return {};
    }

    static ArgPair::Kind toArgPairKind(ebpf_argument_type_t t) {
        switch (t) {
        case EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL: return ArgPair::Kind::PTR_TO_READABLE_MEM_OR_NULL;
        case EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM: return ArgPair::Kind::PTR_TO_READABLE_MEM;
        case EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM: return ArgPair::Kind::PTR_TO_WRITABLE_MEM;
        default: break;
        }
        return {};
    }

    auto makeCall(int32_t imm) const {
        EbpfHelperPrototype proto = info.platform->get_helper_prototype(imm);
        if (proto.return_type == EBPF_RETURN_TYPE_UNSUPPORTED) {
            throw std::runtime_error(std::string("Unsupported function: ") + proto.name);
        }
        Call res;
        res.func = imm;
        res.name = proto.name;
        res.reallocate_packet = proto.reallocate_packet;
        res.is_map_lookup = proto.return_type == EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL;
        std::array<ebpf_argument_type_t, 7> args = {{
            EBPF_ARGUMENT_TYPE_DONTCARE,
            proto.argument_type[0],
            proto.argument_type[1],
            proto.argument_type[2],
            proto.argument_type[3],
            proto.argument_type[4],
            EBPF_ARGUMENT_TYPE_DONTCARE}};
        for (size_t i = 1; i < args.size() - 1; i++) {
            switch (args[i]) {
            case EBPF_ARGUMENT_TYPE_UNSUPPORTED: {
                throw std::runtime_error(std::string("Unsupported function: ") + proto.name);
            }
            case EBPF_ARGUMENT_TYPE_DONTCARE: return res;
            case EBPF_ARGUMENT_TYPE_ANYTHING:
            case EBPF_ARGUMENT_TYPE_PTR_TO_MAP:
            case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_OF_PROGRAMS:
            case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY:
            case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE:
            case EBPF_ARGUMENT_TYPE_PTR_TO_CTX:
                res.singles.push_back({toArgSingleKind(args[i]), Reg{(uint8_t)i}});
                break;
            case EBPF_ARGUMENT_TYPE_CONST_SIZE: assert(false); continue;
            case EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO: assert(false); continue;
            case EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL:
            case EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM:
            case EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM:
                bool can_be_zero = (args[i + 1] == EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO);
                res.pairs.push_back({toArgPairKind(args[i]), Reg{(uint8_t)i}, Reg{(uint8_t)(i + 1)}, can_be_zero});
                i++;
                break;
            }
        }
        return res;
    }

    auto makeJmp(ebpf_inst inst, const vector<ebpf_inst>& insts, pc_t pc) -> Instruction {
        switch ((inst.opcode >> 4) & 0xF) {
        case 0x8:
            if (inst.opcode & INST_SRC_REG)
                throw InvalidInstruction(pc, "Bad instruction");
            if (!info.platform->is_helper_usable(inst.imm))
                throw InvalidInstruction(pc, "invalid helper function id");
            return makeCall(inst.imm);
        case 0x9:
            if ((inst.opcode & INST_CLS_MASK) != INST_CLS_JMP)
                throw InvalidInstruction(pc, "Bad instruction");
            return Exit{};
        case 0x0:
            if ((inst.opcode & INST_CLS_MASK) != INST_CLS_JMP)
                throw InvalidInstruction(pc, "Bad instruction");
        default: {
            pc_t new_pc = pc + 1 + inst.offset;
            if (new_pc >= insts.size())
                throw InvalidInstruction(pc, "jump out of bounds");
            else if (insts[new_pc].opcode == 0)
                throw InvalidInstruction(pc, "jump to middle of lddw");

            auto cond = inst.opcode == INST_OP_JA ? std::optional<Condition>{}
                                                  : Condition{
                                                        .op = getJmpOp(pc, inst.opcode),
                                                        .left = Reg{inst.dst},
                                                        .right = (inst.opcode & INST_SRC_REG) ? (Value)Reg{inst.src}
                                                                                              : Imm{sign_extend(inst.imm)},
                                                        .is64 = ((inst.opcode & INST_CLS_MASK) == INST_CLS_JMP)
                                                    };
            return Jmp{
                .cond = cond,
                .target = label_t{new_pc},
            };
        }
        }
    }

    vector<LabeledInstruction> unmarshal(vector<ebpf_inst> const& insts, vector<btf_line_info_t> const& line_info) {
        vector<LabeledInstruction> prog;
        int exit_count = 0;
        if (insts.empty()) {
            throw std::invalid_argument("Zero length programs are not allowed");
        }
        for (size_t pc = 0; pc < insts.size();) {
            ebpf_inst inst = insts[pc];
            Instruction new_ins;
            bool lddw = false;
            bool fallthrough = true;
            switch (inst.opcode & INST_CLS_MASK) {
            case INST_CLS_LD:
                if (inst.opcode == INST_OP_LDDW_IMM) {
                    int32_t next_imm = pc < insts.size() - 1 ? insts[pc + 1].imm : 0;
                    new_ins = makeLddw(inst, next_imm, insts, static_cast<pc_t>(pc));
                    lddw = true;
                    break;
                }
                // fallthrough
            case INST_CLS_LDX:
            case INST_CLS_ST:
            case INST_CLS_STX: new_ins = makeMemOp(pc, inst); break;

            case INST_CLS_ALU:
            case INST_CLS_ALU64: new_ins = makeAluOp(pc, inst); break;

            case INST_CLS_JMP32:
            case INST_CLS_JMP: {
                new_ins = makeJmp(inst, insts, static_cast<pc_t>(pc));
                if (std::holds_alternative<Exit>(new_ins)) {
                    fallthrough = false;
                    exit_count++;
                }
                if (std::holds_alternative<Jmp>(new_ins)) {
                    if (!std::get<Jmp>(new_ins).cond)
                        fallthrough = false;
                }
                break;
            }
            }
            if (pc == insts.size() - 1 && fallthrough)
                note("fallthrough in last instruction");

            std::optional<btf_line_info_t> current_line_info = {};

            if (pc < line_info.size())
                current_line_info = line_info[pc];

            prog.emplace_back(label_t(static_cast<int>(pc)), new_ins, current_line_info);

            pc++;
            note_next_pc();
            if (lddw) {
                pc++;
                note_next_pc();
            }
        }
        if (exit_count == 0)
            note("no exit instruction");
        return prog;
    }
};

std::variant<InstructionSeq, std::string> unmarshal(const raw_program& raw_prog, vector<vector<string>>& notes) {
    global_program_info = raw_prog.info;
    try {
        return Unmarshaller{notes, raw_prog.info}.unmarshal(raw_prog.prog, raw_prog.line_info);
    } catch (InvalidInstruction& arg) {
        std::ostringstream ss;
        ss << arg.pc << ": " << arg.what() << "\n";
        return ss.str();
    }
}

std::variant<InstructionSeq, std::string> unmarshal(const raw_program& raw_prog) {
    vector<vector<string>> notes;
    return unmarshal(raw_prog, notes);
}

Call make_call(int imm, const ebpf_platform_t& platform)
{
    vector<vector<string>> notes;
    program_info info{.platform = &platform};
    return Unmarshaller{notes, info}.makeCall(imm);
}
