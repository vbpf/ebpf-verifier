#include <assert.h>
#include <vector>
#include <string>
#include <cstring> // memcmp

#include "linux_ebpf.hpp"
#include "asm.hpp"
#include "prototypes.hpp"

using std::vector;
using std::string;

// implemented in asm_marshal
vector<ebpf_inst> marshal(Instruction ins, uint16_t pc);

vector<ebpf_inst> marshal(vector<Instruction> insts);

template <typename T> 
void compare(string field, T actual, T expected) {
    if (actual != expected)
        std::cerr << field << ": (actual) " << std::hex << (int)actual << " != " << (int)expected << " (expected)\n";
}


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
            switch (inst.imm) {
                case 16: return Un::Op::LE16;
                case 32: 
                    if ((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU64)
                        throw InvalidInstruction("invalid endian immediate 32 for 64 bit instruction");
                    return Un::Op::LE32;
                case 64: 
                    if ((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU)
                        throw InvalidInstruction("invalid endian immediate 64 for 32 bit instruction");
                    return Un::Op::LE64;
                default:
                    note("invalid endian immediate; falling back to 64");
                    return Un::Op::LE64;
            }
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

static auto getJmpOp(uint8_t opcode) -> Condition::Op {
    switch ((opcode >> 4) & 0xF) {
        case 0x0 : assert(false); // goto
        case 0x1 : return Condition::Op::EQ;
        case 0x2 : return Condition::Op::GT;
        case 0x3 : return Condition::Op::GE;
        case 0x4 : return Condition::Op::SET;
        case 0x5 : return Condition::Op::NE;
        case 0x6 : return Condition::Op::SGT;
        case 0x7 : return Condition::Op::SGE;
        case 0x8 : assert(false); // call
        case 0x9 : assert(false); // exit
        case 0xa : return Condition::Op::LT;
        case 0xb : return Condition::Op::LE;
        case 0xc : return Condition::Op::SLT;
        case 0xd : return Condition::Op::SLE;
        case 0xe : throw InvalidInstruction{"Invalid JMP op 0xe"};
    }
    assert(false);
}

static int access_width(uint8_t opcode)
{
    switch (opcode & EBPF_SIZE_MASK) {
        case EBPF_SIZE_B: return 1;
        case EBPF_SIZE_H: return 2;
        case EBPF_SIZE_W: return 4;
        case EBPF_SIZE_DW: return 8;
    }
	assert(false);
}

static auto makeMemOp(ebpf_inst inst) -> Instruction {
    if (inst.dst > 10 || inst.src > 10) note("Bad register");

    Width width = getMemWidth(inst.opcode);
    bool isLD = (inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_LD;
    switch ((inst.opcode & EBPF_MODE_MASK) >> 5) {
        case 0:
            compare("fail:", inst.opcode, (uint8_t)0x11);
            assert(false);
        case EBPF_ABS:
            if (!isLD) throw UnsupportedMemoryMode{"ABS but not LD"};
            if (width == Width::DW) note("invalid opcode LDABSDW");
            return Packet{
                .width = width,
                .offset = inst.imm,
                .regoffset = {}
            };

        case EBPF_IND:
            if (!isLD) throw UnsupportedMemoryMode{"IND but not LD"};
            if (width == Width::DW) note("invalid opcode LDINDDW");
            return Packet{
                .width = width,
                .offset = inst.imm,
                .regoffset = Reg{inst.src}
            };

        case EBPF_MEM:
        {
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

        case EBPF_LEN:
            throw UnsupportedMemoryMode{"LEN"};

        case EBPF_MSH:
            throw UnsupportedMemoryMode{"MSH"};

        case EBPF_XADD:
            return LockAdd {
                .width = width,
                .valreg = Reg{inst.src},
                .basereg = Reg{inst.dst},
                .offset = inst.offset,
            };
        case EBPF_MEM_UNUSED: throw UnsupportedMemoryMode{"Memory mode 7"};
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

static auto makeLddw(ebpf_inst inst, int32_t next_imm, const vector<ebpf_inst>& insts, uint16_t pc) -> Instruction {
    if (pc >= insts.size() - 1) note("incomplete LDDW");
    if (inst.src > 1 || inst.dst > 10 || inst.offset != 0)
        note("LDDW uses reserved fields");

    if (inst.src == 1) {
        // magic number, meaning we're a per-process file descriptor defining the map.
        // (for details, look for BPF_PSEUDO_MAP_FD in the kernel)
        return LoadMapFd{
            .dst = Reg{inst.dst},
            .mapfd = inst.imm
         };
    }

    ebpf_inst next = insts[pc+1];
    if (next.opcode != 0 || next.dst != 0 || next.src != 0 || next.offset != 0) 
        note("invalid LDDW");
    return Bin{
        .op = Bin::Op::MOV,
        .is64 = true,
        .dst = Reg{ inst.dst },
        .v = Imm{ merge(inst.imm, next_imm) },
        .lddw = true,
    };
}

static auto makeJmp(ebpf_inst inst, const vector<ebpf_inst>& insts, uint16_t pc) -> Instruction {
    switch (inst.opcode) {
        case EBPF_OP_CALL:
            if (!is_valid_prototype(inst.imm)) note("invalid function id ");
            return Call{ inst.imm };
        case EBPF_OP_EXIT: return Exit{};
        default: {
            uint16_t new_pc = pc + 1 + inst.offset;
            if (new_pc >= insts.size()) note("jump out of bounds");
            if (insts[new_pc].opcode == 0) note("jump to middle of lddw");

            auto cond = inst.opcode == EBPF_OP_JA ? std::optional<Condition>{} : Condition{
                .op = getJmpOp(inst.opcode),
                .left = Reg{inst.dst},
                .right = (inst.opcode & EBPF_SRC_REG) ? (Value)Reg{inst.src} : Imm{inst.imm},
            };
            return Jmp {
                .cond = cond,
                .target = std::to_string(new_pc),
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
        throw std::invalid_argument("Zero length programs are not allowed");
    }
    note_next_pc();
    for (uint16_t pc = 0; pc < insts.size();) {
        ebpf_inst inst = insts[pc];
        vector<Instruction> new_ins;
        switch (inst.opcode & EBPF_CLS_MASK) {
            case EBPF_CLS_LD:
                if (inst.opcode == EBPF_OP_LDDW_IMM) {
                    uint32_t next_imm = pc < insts.size() - 1 ? insts[pc+1].imm : 0;
                    new_ins = {makeLddw(inst, next_imm, insts, pc),
                               Undefined{0}};
                    break;
                }
                //fallthrough
            case EBPF_CLS_LDX:
            case EBPF_CLS_ST: case EBPF_CLS_STX:
                new_ins = {makeMemOp(inst)};
                break;

            case EBPF_CLS_ALU: case EBPF_CLS_ALU64: 
                new_ins = {makeAluOp(inst)};
                break;

            case EBPF_CLS_JMP: {
                new_ins = {makeJmp(inst, insts, pc)};
                if (std::holds_alternative<Exit>(new_ins[0]))
                    exit_count++;
                break;
            }

            case EBPF_CLS_UNUSED:
                throw InvalidInstruction{"Invalid class 0x6"};
        }
        vector<ebpf_inst> marshalled = marshal(new_ins[0], pc);
        ebpf_inst actual = marshalled[0];
        if (std::memcmp(&actual, &inst, sizeof(inst))) {
            std::cerr << "new: " << IndexedInstruction{pc, new_ins[0]} << "\n";
            compare("opcode", actual.opcode, inst.opcode);
            compare("dst", actual.dst, inst.dst);
            compare("src", actual.src, inst.src);
            compare("offset", actual.offset, inst.offset);
            compare("imm", actual.imm, inst.imm);
            std::cerr << "\n";
        }
        for (auto ins : new_ins) {
            prog.push_back(ins);
            pc++;
            note_next_pc();
        }
    }
    if (exit_count == 0) note("no exit instruction");
    return res;
}

std::variant<Program, string> parse(std::istream& is, size_t nbytes) {
    if (nbytes % sizeof(ebpf_inst) != 0) {
        note(string("file size must be a multiple of ") + std::to_string(sizeof(ebpf_inst)));
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
        std::cerr << arg.what() << "\n";
        return arg.what();
    }
}
