
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

static auto getMemIsLoad(uint8_t opcode) -> bool {
    switch (opcode & EBPF_CLS_MASK) {
        case EBPF_CLS_ST : return false;
        case EBPF_CLS_STX: return false;
        case EBPF_CLS_LD : return true;
        case EBPF_CLS_LDX: return true;
    }
    return {};
}

static auto getMemWidth(uint8_t opcode) -> Width {
    switch (opcode & EBPF_SIZE_MASK) {
        case EBPF_SIZE_B : return Width::B;
        case EBPF_SIZE_H : return Width::H;
        case EBPF_SIZE_W : return Width::W;
        case EBPF_SIZE_DW: return Width::DW;
    }
	return {};
}

static auto getMemX(uint8_t opcode) -> bool {
    switch (opcode & EBPF_CLS_MASK) {
        case EBPF_CLS_LD : return false; 
        case EBPF_CLS_ST : return false;
        case EBPF_CLS_LDX: return true;
        case EBPF_CLS_STX: return true;
    }
    return {};
}

static auto getBinOp(uint8_t opcode) -> Bin::Op {
    switch ((opcode >> 4) & 0xF) {
        case 0x0 : return Bin::Op::ADD;
        case 0x1 : return Bin::Op::SUB;
        case 0x2 : return Bin::Op::MUL;
        case 0x3 : return Bin::Op::DIV;
        case 0x4 : return Bin::Op::OR;
        case 0x5 : return Bin::Op::AND;
        case 0x6 : return Bin::Op::LSH;
        case 0x7 : return Bin::Op::RSH;

        case 0x9 : return Bin::Op::MOD;
        case 0xa : return Bin::Op::XOR;
        case 0xb : return Bin::Op::MOV;
        case 0xc: return Bin::Op::ARSH;
    }
    return {};
}

static auto getBinValue(ebpf_inst inst) -> Value {
    if (inst.opcode & EBPF_SRC_REG)
        return Reg{inst.src};
    else
        return Imm{inst.imm};
}

static auto getUnOp(uint8_t opcode) -> Un::Op {
    switch (opcode) {
        case EBPF_OP_NEG: return Un::Op::NEG;
        case EBPF_OP_LE : return Un::Op::LE;
        case EBPF_OP_BE : return Un::Op::BE;
    }
    return {};
}

static auto getJmpOp(uint8_t opcode) -> Jmp::Op {
    switch (opcode | EBPF_SRC_REG) {
        
        case EBPF_OP_JEQ_REG : return Jmp::Op::EQ;
        case EBPF_OP_JGT_REG : return Jmp::Op::GT;
        case EBPF_OP_JGE_REG : return Jmp::Op::GE;
        case EBPF_OP_JSET_REG: return Jmp::Op::SET;
        case EBPF_OP_JNE_REG : return Jmp::Op::NE;
        case EBPF_OP_JSGT_REG: return Jmp::Op::SGT;
        case EBPF_OP_JSGE_REG: return Jmp::Op::SGE;


        case EBPF_OP_JLT_REG : return Jmp::Op::LT;
        case EBPF_OP_JLE_REG : return Jmp::Op::LE;
        case EBPF_OP_JSLT_REG: return Jmp::Op::SLT;
        case EBPF_OP_JSLE_REG: return Jmp::Op::SLE;

    }
    return {};
}

static auto makeMemOp(ebpf_inst inst) -> Instruction {
    auto width = getMemWidth(inst.opcode);
    auto mode = inst.opcode & EBPF_MODE_MASK;
    switch (mode) {
        case EBPF_MODE_MEM: {
            bool isLoad = getMemIsLoad(inst.opcode);
            return Mem{ 
                .isLoad = isLoad,
                .width = width,
                .valreg = Reg{isLoad ? inst.dst : inst.src},
                .basereg = Reg{isLoad ? inst.src : inst.dst},
                .offset = (inst.opcode & 1) ? (Target)Offset{inst.offset} : Reg{inst.imm},
            };
        }
        case EBPF_MODE_ABS: return Packet{width, inst.imm, {} };
        case EBPF_MODE_IND: return Packet{width, inst.imm, Reg{inst.src} };
        case EBPF_MODE_LEN: return {};
        case EBPF_MODE_MSH: return {};
        case EBPF_XADD: return LockAdd {
            .width = width,
            .valreg = Reg{inst.src},
            .basereg = Reg{inst.dst},
            .offset = inst.offset,
        };
    }
    return Undefined{inst.opcode};
}

static auto makeAluOp(ebpf_inst inst) -> Instruction {
    if (inst.opcode == EBPF_OP_NEG || inst.opcode == EBPF_OP_BE || inst.opcode == EBPF_OP_LE) {
        return Un{ 
            .op = getUnOp(inst.opcode),
            .dst=inst.dst 
        };
    } else {
        return Bin{ 
            .op = getBinOp(inst.opcode), 
            .is64 = (inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU64,
            .dst = Reg{ inst.dst },
            .v = getBinValue(inst),
        };
    }
}

static auto toasm(ebpf_inst inst, int32_t next_imm) -> Instruction {
    if (inst.opcode == EBPF_OP_LDDW_IMM) {
        uint64_t imm = (uint64_t(next_imm) << 32 | (uint32_t)inst.imm);
        return Bin{
            .op = Bin::Op::MOV,
            .is64 = true,
            .dst = Reg{ inst.dst },
            .v = Imm{ imm },
            .lddw = true,
        };
    }
    switch (inst.opcode & EBPF_CLS_MASK) {
        case EBPF_CLS_LD: case EBPF_CLS_LDX:
        case EBPF_CLS_ST: case EBPF_CLS_STX:
            return makeMemOp(inst);

        case EBPF_CLS_ALU:
        case EBPF_CLS_ALU64: 
            return makeAluOp(inst);

        case EBPF_CLS_JMP: 
            if (inst.opcode == EBPF_OP_JA) return Goto{ inst.offset };
            else if (inst.opcode == EBPF_OP_CALL) return Call{ inst.imm };
            else if (inst.opcode == EBPF_OP_EXIT) return Exit{};
            else return Jmp{
                .op = getJmpOp(inst.opcode),
                .left = Reg{inst.dst},
                .right = (inst.opcode & EBPF_SRC_REG) ? (Value)Reg{inst.src} : Imm{inst.imm},
                .offset = inst.offset,
            };
        case EBPF_CLS_UNUSED: return Undefined{};
    }
    return {};
}

auto toasm(uint16_t pc, ebpf_inst inst, int32_t next_imm) -> IndexedInstruction {
    return {pc, toasm(inst, next_imm)};
}

bool parse(vector<ebpf_inst> insts, vector<Instruction>& prog, string& errmsg)
{
    if (insts.size() == 0) {
        errmsg = "Zero length programs are not allowed";
        return false;
    }
    int exit_count = 0;
    for (uint32_t pc = 0; pc < insts.size(); pc++) {
        ebpf_inst inst = insts[pc];
        uint32_t next_imm = pc < insts.size() - 1 ? insts[pc+1].imm : 0;
        prog.push_back(toasm(pc, inst, next_imm).ins);

        if (is_alu(inst.opcode)) {
            if (inst.dst == 10) {
                errmsg = string("Invalid target r10 at PC ") + std::to_string(pc);
                return false;
            }
        }
        switch (inst.opcode) {

        case EBPF_OP_LE:
        case EBPF_OP_BE:
            if (inst.imm != 16 && inst.imm != 32 && inst.imm != 64) {
                errmsg = string("invalid endian immediate at PC ") + std::to_string(pc);
                return false;
            }
            break;

        case EBPF_OP_DIV_IMM:
        case EBPF_OP_MOD_IMM:
        case EBPF_OP_DIV64_IMM:
        case EBPF_OP_MOD64_IMM:
            if (inst.imm == 0) {
                errmsg = string("division by zero at PC ") + std::to_string(pc);
                return false;
            }
            // fallthrough            
        case EBPF_OP_ADD_IMM:
        case EBPF_OP_SUB_IMM:
        case EBPF_OP_MUL_IMM:
        case EBPF_OP_OR_IMM:
        case EBPF_OP_AND_IMM:
        case EBPF_OP_LSH_IMM:
        case EBPF_OP_RSH_IMM:
        case EBPF_OP_NEG:
        case EBPF_OP_XOR_IMM:
        case EBPF_OP_MOV_IMM:

        case EBPF_OP_ADD64_IMM:
        case EBPF_OP_SUB64_IMM:
        case EBPF_OP_MUL64_IMM:
        case EBPF_OP_OR64_IMM:
        case EBPF_OP_AND64_IMM:
        case EBPF_OP_LSH64_IMM:
        case EBPF_OP_RSH64_IMM:
        case EBPF_OP_NEG64:
        case EBPF_OP_XOR64_IMM:
        case EBPF_OP_MOV64_IMM:
        case EBPF_OP_ARSH64_IMM:
            if (inst.src != 0 || inst.offset != 0) {
				errmsg = "nonzero src/offset for register alu op";
				return false;
			}
            break;

        case EBPF_OP_ARSH_REG:
        case EBPF_OP_ARSH_IMM:
            // why?
            errmsg = "arsh32 is not allowed";
            return false;
            break;
        case EBPF_OP_DIV_REG:
        case EBPF_OP_ADD_REG:
        case EBPF_OP_SUB_REG:
        case EBPF_OP_MUL_REG:
        case EBPF_OP_OR_REG:
        case EBPF_OP_AND_REG:
        case EBPF_OP_LSH_REG:
        case EBPF_OP_RSH_REG:
        case EBPF_OP_MOD_REG:
        case EBPF_OP_XOR_REG:
        case EBPF_OP_MOV_REG:

        case EBPF_OP_ADD64_REG:
        case EBPF_OP_SUB64_REG:
        case EBPF_OP_MUL64_REG:
        case EBPF_OP_DIV64_REG:
        case EBPF_OP_OR64_REG:
        case EBPF_OP_AND64_REG:
        case EBPF_OP_LSH64_REG:
        case EBPF_OP_RSH64_REG:
        case EBPF_OP_MOD64_REG:
        case EBPF_OP_XOR64_REG:
        case EBPF_OP_MOV64_REG:
        case EBPF_OP_ARSH64_REG:
            if (inst.imm != 0 || inst.offset != 0) {
				errmsg = "nonzero imm/offset for register alu op";
				return false;
			}
            break;
        case EBPF_OP_LDXW:
        case EBPF_OP_LDXH:
        case EBPF_OP_LDXB:
        case EBPF_OP_LDXDW:
            if (inst.src > 10 || inst.dst >= 10) {
                errmsg = string("invalid registers (") + std::to_string(inst.src) + ", " + std::to_string(inst.dst) + ") at PC " + std::to_string(pc);
                return false;
            }
            if (inst.src == 10 && (inst.offset + access_width(inst.opcode) > 0 || inst.offset < -STACK_SIZE)) {
                errmsg = string("Stack access out of bounds at ") + std::to_string(pc);
                return false;
            }
            break;

        case EBPF_OP_LDABSW:
        case EBPF_OP_LDABSH:
        case EBPF_OP_LDABSB:
        
        case EBPF_OP_LDXABSW:
        case EBPF_OP_LDXABSH:
        case EBPF_OP_LDXABSB:
        case EBPF_OP_LDXABSDW:

        case EBPF_OP_LDINDW:
        case EBPF_OP_LDINDH:
        case EBPF_OP_LDINDB:

        case EBPF_OP_LDXINDW:
        case EBPF_OP_LDXINDH:
        case EBPF_OP_LDXINDB:
        case EBPF_OP_LDXINDDW:

            if (inst.src > 10 || inst.dst >= 10) {
                errmsg = string("invalid registers (") + std::to_string(inst.src) + ", " + std::to_string(inst.dst) + ") at PC " + std::to_string(pc);
                return false;
            }
            break;
        case EBPF_OP_STW:
        case EBPF_OP_STH:
        case EBPF_OP_STB:
        case EBPF_OP_STDW:
        case EBPF_OP_STXW:
        case EBPF_OP_STXH:
        case EBPF_OP_STXB:
        case EBPF_OP_STXDW:
            if (inst.src > 10 || inst.dst > 10) {
                errmsg = string("invalid registers (") + std::to_string(inst.src) + ", " + std::to_string(inst.dst) + ") at PC " + std::to_string(pc);
                return false;
            }
            if (inst.dst == 10 && (inst.offset + access_width(inst.opcode) > 0 || inst.offset < -STACK_SIZE)) {
                errmsg = string("Stack access out of bounds at ") + std::to_string(pc);
                return false;
            }
            break;

        case EBPF_OP_LDINDDW:
            errmsg = "invalid opcode EBPF_OP_LDINDDW";
            return false;

        case EBPF_OP_LDABSDW:
            errmsg = "invalid opcode EBPF_OP_LDABSDW";
            return false;

        case EBPF_OP_STABSDW:
            errmsg = "invalid opcode EBPF_OP_STABSDW";
            return false;

        case EBPF_STXADDW:     
        case EBPF_STXADDDW:

        case EBPF_OP_STABSW:
        case EBPF_OP_STABSH:
        case EBPF_OP_STABSB:
        case EBPF_OP_STXABSW:
        case EBPF_OP_STXABSH:
        case EBPF_OP_STXABSB:
        case EBPF_OP_STXABSDW:
        case EBPF_OP_STINDW:
        case EBPF_OP_STINDH:
        case EBPF_OP_STINDB:
        case EBPF_OP_STINDDW:
        case EBPF_OP_STXINDW:
        case EBPF_OP_STXINDH:
        case EBPF_OP_STXINDB:
        case EBPF_OP_STXINDDW:
            if (inst.src > 10 || inst.dst > 10) {
                errmsg = string("invalid registers (") + std::to_string(inst.src) + ", " + std::to_string(inst.dst) + ") at PC " + std::to_string(pc);
                return false;
            }
            break;

        case EBPF_OP_LDDW_IMM:
            if (pc + 1 >= insts.size()) {
                errmsg = string("incomplete lddw at PC ") + std::to_string(pc);
                return false;
            }
            if (inst.src > 1 || inst.dst > 10 || inst.offset != 0) {
                errmsg = string("LDDS uses reserved fields at PC ") + std::to_string(pc);
                return false;
            }
            {
                ebpf_inst next = insts[pc+1];
                if (next.opcode != 0 || next.dst != 0 || next.src != 0 || next.offset != 0) {
                    errmsg = string("invalid lddw at PC ") + std::to_string(pc);
                    return false;
                }
            }
            prog.push_back(Undefined{0});
            pc++; /* Skip next instruction */
            break;

        case EBPF_OP_JA:
        case EBPF_OP_JEQ_REG:
        case EBPF_OP_JEQ_IMM:
        case EBPF_OP_JGT_REG:
        case EBPF_OP_JGT_IMM:
        case EBPF_OP_JGE_REG:
        case EBPF_OP_JGE_IMM:
        case EBPF_OP_JLT_REG:
        case EBPF_OP_JLT_IMM:
        case EBPF_OP_JLE_REG:
        case EBPF_OP_JLE_IMM:
        case EBPF_OP_JSET_REG:
        case EBPF_OP_JSET_IMM:
        case EBPF_OP_JNE_REG:
        case EBPF_OP_JNE_IMM:
        case EBPF_OP_JSGT_IMM:
        case EBPF_OP_JSGT_REG:
        case EBPF_OP_JSGE_IMM:
        case EBPF_OP_JSGE_REG:
        case EBPF_OP_JSLT_IMM:
        case EBPF_OP_JSLT_REG:
        case EBPF_OP_JSLE_IMM:
        case EBPF_OP_JSLE_REG:
            {
                uint32_t new_pc = pc + 1 + inst.offset;
                if (new_pc >= insts.size()) {
                    errmsg = string("jump out of bounds at PC ") + std::to_string(pc);
                    return false;
                } else if (insts[new_pc].opcode == 0) {
                    errmsg = string("jump to middle of lddw at PC ") + std::to_string(pc);
                    return false;
                }
            }
            break;

        case EBPF_OP_CALL:
            if (!is_valid_prototype(inst.imm)){
                errmsg = string("invalid function id ") + std::to_string(inst.imm) + " at " + std::to_string(pc);
                return false;
            }

            break;

        case EBPF_OP_EXIT:
            exit_count++;
            /*if (exit_count > 1) {
                errmsg = "subprograms are not supported yet";
                return false;
            }*/
            break;

        default: {
            errmsg = string("invalid instruction ") + std::to_string(inst.opcode) + " at " + std::to_string(pc);
            return false;
        }
        }
    }

    if (exit_count >= 1) return true;
    errmsg = "no exit instruction";
    return false;
}

std::variant<Program, string> parse(std::istream& is, size_t nbytes) {
    if (nbytes % sizeof(ebpf_inst) != 0) {
        return std::string("file size must be a multiple of ") + std::to_string(sizeof(ebpf_inst));
    }
    vector<ebpf_inst> binary_code(nbytes / sizeof(ebpf_inst));
    is.read((char*)binary_code.data(), nbytes);
    string errmsg;
    vector<Instruction> insts;
    if (parse(binary_code, insts, errmsg)) {
        Program prog{ insts };
        print(prog);
        if (global_options.check_raw_reachability) {
            if (!check_raw_reachability(prog)) {
                return "No support for forests yet";
            }
        }
        return prog;
    }
    return errmsg;
}
