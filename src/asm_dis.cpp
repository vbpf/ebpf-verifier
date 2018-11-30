
#include <stdarg.h>
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>

#include <memory>
#include <variant>

#include "asm.hpp"
#include "prototypes.hpp"
#include "verifier.hpp"
#include "cfg.hpp"
#include "instructions.hpp"

struct InvalidInstruction : std::invalid_argument {
    InvalidInstruction(const char* what) : std::invalid_argument{what} { }
};

struct UnsupportedInstruction : std::invalid_argument {
    UnsupportedInstruction(const char* what) : std::invalid_argument{what} { }
};

struct UnsupportedMemoryMode : std::invalid_argument {
    UnsupportedMemoryMode(const char* what) : std::invalid_argument{what} { }
};

static std::vector<std::vector<std::string>> notes;
void note(std::string what) {
    notes.back().emplace_back(what);
}
void note_next_pc() {
    notes.emplace_back();
}

static auto getMemIsLoad(uint8_t opcode) -> bool {
    switch (opcode & EBPF_CLS_MASK) {
        case EBPF_CLS_LD : return true;
        case EBPF_CLS_LDX: return true;
        case EBPF_CLS_ST : return false;
        case EBPF_CLS_STX: return false;
    }
    assert(false);
}

static auto getMemWidth(uint8_t opcode) -> Width {
    switch (opcode & EBPF_SIZE_MASK) {
        case EBPF_SIZE_B : return Width::B;
        case EBPF_SIZE_H : return Width::H;
        case EBPF_SIZE_W : return Width::W;
        case EBPF_SIZE_DW: return Width::DW;
    }
	assert(false);
}

static auto getMemX(uint8_t opcode) -> bool {
    switch (opcode & EBPF_CLS_MASK) {
        case EBPF_CLS_LD : return false; 
        case EBPF_CLS_ST : return false;
        case EBPF_CLS_LDX: return true;
        case EBPF_CLS_STX: return true;
    }
    assert(false);
}

static auto getAluOp(ebpf_inst inst) -> std::variant<Bin::Op, Un::Op> {
    switch ((inst.opcode >> 4) & 0xF) {
        case 0x0 : return Bin::Op::ADD;
        case 0x1 : return Bin::Op::SUB;
        case 0x2 : return Bin::Op::MUL;
        case 0x3 : return Bin::Op::DIV;
        case 0x4 : return Bin::Op::OR;
        case 0x5 : return Bin::Op::AND;
        case 0x6 : return Bin::Op::LSH;
        case 0x7 : return Bin::Op::RSH;
        case 0x8 : return Un::Op::NEG;
        case 0x9 : return Bin::Op::MOD;
        case 0xa : return Bin::Op::XOR;
        case 0xb : return Bin::Op::MOV;
        case 0xc :
            if ((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU)
                note("arsh32 is not allowed");
            return Bin::Op::ARSH;
        case 0xd :
            // todo: add class LE, then fail here
            if (inst.imm != 16 && inst.imm != 32 && inst.imm != 64) note("invalid endian immediate");
            return Un::Op::LE;
        case 0xe : throw InvalidInstruction{"Invalid ALU op 0xe"};
    }
    assert(false);
}

static auto getBinValue(ebpf_inst inst) -> Value {
    if (inst.offset != 0) note("nonzero offset for register alu op");
    if (inst.opcode & EBPF_SRC_REG) {
        if (inst.imm != 0) note("nonzero imm for register alu op");
        return Reg{inst.src};
    } else {
        if (inst.src != 0) note("nonzero src for register alu op");
        return Imm{inst.imm};
    }
}

static auto getJmpOp(uint8_t opcode) -> Jmp::Op {
    switch ((opcode >> 4) & 0xF) {
        case 0x0 : assert(false); // goto
        case 0x1 : return Jmp::Op::EQ;
        case 0x2 : return Jmp::Op::GT;
        case 0x3 : return Jmp::Op::GE;
        case 0x4 : return Jmp::Op::SET;
        case 0x5 : return Jmp::Op::NE;
        case 0x6 : return Jmp::Op::SGT;
        case 0x7 : return Jmp::Op::SGE;
        case 0x8 : assert(false); // call
        case 0x9 : assert(false); // exit
        case 0xa : return Jmp::Op::LT;
        case 0xb : return Jmp::Op::LE;
        case 0xc : return Jmp::Op::SLT;
        case 0xd : return Jmp::Op::SLE;
        case 0xe : throw InvalidInstruction{"Invalid JMP op 0xe"};
    }
    assert(false);
}

static auto makeMemOp(ebpf_inst inst) -> Instruction {
    if (inst.dst > 10 || inst.src > 10) note("Bad register");

    Width width = getMemWidth(inst.opcode);
    int mode = (inst.opcode & EBPF_MODE_MASK) >> 5;
    bool isLD = (inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_LD;
    switch (mode) {
        case 0: assert(false);
        case 1: // EBPF_MODE_ABS: 
            if (!isLD) throw UnsupportedMemoryMode{"ABS but not LD"};
            if (width == Width::DW) note("invalid opcode LDABSDW");
            return Packet{width, inst.imm, {} };

        case 2: //EBPF_MODE_IND:
            if (!isLD) throw UnsupportedMemoryMode{"IND but not LD"};
            if (width == Width::DW) note("invalid opcode LDINDDW");
            return Packet{width, inst.imm, Reg{inst.src} };

        case 3: {
            if (isLD) throw UnsupportedMemoryMode{"plain LD"};
            bool isLoad = getMemIsLoad(inst.opcode);
            if (isLoad && inst.dst == 10) note("Cannot modify r10");
            bool isImm = !(inst.opcode & 1);
            assert(!(isLoad && isImm));
            int basereg = isLoad ? inst.src : inst.dst;
            if (basereg == 10 && (inst.offset + access_width(inst.opcode) > 0 || inst.offset < -STACK_SIZE)) {
                note("Stack access out of bounds");
            }
            return Mem{ 
                .width = width,
                .basereg = Reg{basereg},
                .offset = inst.offset,
                .value = isLoad ? (Mem::Value)Mem::Load{inst.dst}
                       : (isImm ? (Mem::Value)Mem::StoreImm{inst.imm}
                                : (Mem::Value)Mem::StoreReg{inst.src}),
            };
        }

        case 4: //EBPF_MODE_LEN:
            throw UnsupportedMemoryMode{"LEN"};

        case 5: //EBPF_MODE_MSH:
            throw UnsupportedMemoryMode{"MSH"};

        case 6: //EBPF_XADD:
            return LockAdd {
                .width = width,
                .valreg = Reg{inst.src},
                .basereg = Reg{inst.dst},
                .offset = inst.offset,
            };
        case 7: throw UnsupportedMemoryMode{"Memory mode 7"};
    }
    assert(false);
}

static auto makeAluOp(ebpf_inst inst) -> Instruction {
    if (inst.dst == 10) note("Invalid target r10");
    return std::visit(overloaded{
        [&](Un::Op op) -> Instruction { return Un{ .op = op, .dst = inst.dst }; },
        [&](Bin::Op op) -> Instruction {
            Bin res{ 
                .op = op,
                .is64 = (inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU64,
                .dst = Reg{ inst.dst },
                .v = getBinValue(inst),
            };
            if (op == Bin::Op::DIV || op == Bin::Op::MOD)
                if (std::holds_alternative<Imm>(res.v) && std::get<Imm>(res.v).v == 0)
                    note("division by zero");
            return res;
        }
    }, getAluOp(inst));
}

static auto makeLddw(ebpf_inst inst, int32_t next_imm, const vector<ebpf_inst>& insts, uint32_t pc) -> Bin {
    /*
    if (inst.src == 1) {
        // magic number, meaning we're a per-process file descriptor
        // defining the map.
        // (for details, look for BPF_PSEUDO_MAP_FD in the kernel)
        // This is what ARG_CONST_MAP_PTR looks for

        // This is probably the wrong thing to do. should we add an FD type?
        // Here we (probably) need the map structure
        block.assign(machine.regs[bin.dst].region, T_MAP);
        block.assign(machine.regs[bin.dst].offset, 0);
        return { &block };
    }
    */
    if (pc + 1 >= insts.size()) note("incomplete LDDW");
    if (inst.src > 1 || inst.dst > 10 || inst.offset != 0)
        note("LDDW uses reserved fields");
    ebpf_inst next = insts[pc+1];
    if (next.opcode != 0 || next.dst != 0 || next.src != 0 || next.offset != 0) 
        note("invalid LDDW");

    uint64_t imm = (((uint64_t)next_imm) << 32) | (uint32_t)inst.imm;
    return Bin{
        .op = Bin::Op::MOV,
        .is64 = true,
        .dst = Reg{ inst.dst },
        .v = Imm{ imm },
        .lddw = true,
    };
}

static auto makeJmp(ebpf_inst inst, const vector<ebpf_inst>& insts, uint32_t pc) -> Instruction {
    switch (inst.opcode) {
        case EBPF_OP_JA  : return Goto{ inst.offset };
        case EBPF_OP_CALL:
            if (!is_valid_prototype(inst.imm)) note("invalid function id ");
            return Call{ inst.imm };
        case EBPF_OP_EXIT: return Exit{};
        default: {
            uint32_t new_pc = pc + 1 + inst.offset;
            if (new_pc >= insts.size()) note("jump out of bounds");
            if (insts[new_pc].opcode == 0) note("jump to middle of lddw");

            if (inst.opcode == EBPF_OP_JA) return Goto{ inst.offset };
            return Jmp{
                .op = getJmpOp(inst.opcode),
                .left = Reg{inst.dst},
                .right = (inst.opcode & EBPF_SRC_REG) ? (Value)Reg{inst.src} : Imm{inst.imm},
                .offset = inst.offset,
            };
        }
    }
}

Program parse(vector<ebpf_inst> insts)
{
    Program res;
    vector<Instruction>& prog = res.code;
    int exit_count = 0;
    if (insts.size() == 0) {
        note("Zero length programs are not allowed");
        return res;
    }
    for (uint32_t pc = 0; pc < insts.size(); pc++) {
        ebpf_inst inst = insts[pc];
        note_next_pc();
        switch (inst.opcode & EBPF_CLS_MASK) {
            case EBPF_CLS_LD:
                if (inst.opcode == EBPF_OP_LDDW_IMM) {
                    uint32_t next_imm = pc < insts.size() - 1 ? insts[pc+1].imm : 0;
                    prog.push_back(makeLddw(inst, next_imm, insts, pc));
                    prog.push_back(Undefined{0});
                    pc++;
                    note_next_pc();
                    break;
                }
                //fallthrough
            case EBPF_CLS_LDX:
            case EBPF_CLS_ST: case EBPF_CLS_STX:
                prog.push_back(makeMemOp(inst));
                break;

            case EBPF_CLS_ALU: case EBPF_CLS_ALU64: 
                prog.push_back(makeAluOp(inst));
                break;

            case EBPF_CLS_JMP: {
                auto ins = makeJmp(inst, insts, pc);
                if (std::holds_alternative<Exit>(ins))
                    exit_count++;
                prog.push_back(ins);
                break;
            }

            case EBPF_CLS_UNUSED:
                throw InvalidInstruction{"Invalid class 0x6"};
        }       
    }
    if (exit_count == 0) note("no exit instruction");

    if (global_options.check_raw_reachability) {
        if (!check_raw_reachability(res)) {
            note("No support for forests yet");
        }
    }
    return res;
}

std::variant<Program, string> parse(std::istream& is, size_t nbytes) {
    if (nbytes % sizeof(ebpf_inst) != 0) {
        return std::string("file size must be a multiple of ") + std::to_string(sizeof(ebpf_inst));
    }
    vector<ebpf_inst> binary_code(nbytes / sizeof(ebpf_inst));
    is.read((char*)binary_code.data(), nbytes);
    try {
        auto res = parse(binary_code);
        int pc = 0;
        for (auto notelist : notes) {
            pc++;
            for (auto s : notelist) {
                std::cout << "Note (" << pc << "): " << s << "\n";
            }
        }
        return res;
    } catch (InvalidInstruction& arg) {
        return arg.what();
    }
}
