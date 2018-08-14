#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>

#include "verifier.hpp"

bool validate_simple(vector<ebpf_inst> insts, string& errmsg)
{
    if (insts.size() == 0) {
        errmsg = "Zero length programs are not allowed";
        return false;
    }
    for (uint32_t pc = 0; pc < insts.size(); pc++) {
        ebpf_inst inst = insts[pc];

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
        case EBPF_OP_ARSH_IMM:

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
        case EBPF_OP_ARSH_REG:

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

            if (inst.src == 10 && (inst.offset + access_width(inst.opcode) > 0 || inst.offset < -STACK_SIZE)) {
                errmsg = string("Stack access out of bounds at ") + std::to_string(pc);
                return false;
            }
            break;
        case EBPF_OP_LDABSW:
        case EBPF_OP_LDABSH:
        case EBPF_OP_LDABSB:
        case EBPF_OP_LDABSDW:
        case EBPF_OP_LDXABSW:
        case EBPF_OP_LDXABSH:
        case EBPF_OP_LDXABSB:
        case EBPF_OP_LDXABSDW:
        case EBPF_OP_LDINDW:
        case EBPF_OP_LDINDH:
        case EBPF_OP_LDINDB:
        case EBPF_OP_LDINDDW:
        case EBPF_OP_LDXINDW:
        case EBPF_OP_LDXINDH:
        case EBPF_OP_LDXINDB:
        case EBPF_OP_LDXINDDW:

            if (inst.dst == 10) {
                errmsg = string("invalid destination register at PC ") + std::to_string(pc);
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
            if (inst.dst == 10 && (inst.offset + access_width(inst.opcode) > 0 || inst.offset < -STACK_SIZE)) {
                errmsg = string("Stack access out of bounds at ") + std::to_string(pc);
                return false;
            }

        case EBPF_STXADDW:     
        case EBPF_STXADDDW:

        case EBPF_OP_STABSW:
        case EBPF_OP_STABSH:
        case EBPF_OP_STABSB:
        case EBPF_OP_STABSDW:
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
 
            break;

        case EBPF_OP_LDDW:
            if (pc + 1 >= insts.size() || insts[pc+1].opcode != 0) {
                errmsg = string("incomplete lddw at PC ") + std::to_string(pc);
                return false;
            }
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
            break;

        case EBPF_OP_EXIT:
            break;

        default: {
            errmsg = string("Invalid instruction ") + std::to_string(inst.opcode) + " at " + std::to_string(pc);
            return false;
        }
        }
    }

    return true;
}
