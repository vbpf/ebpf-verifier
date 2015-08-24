#!/usr/bin/env python
"""
eBPF assembler

Very simple single-pass assembler. Only exists to assemble testcases
for the interpreter.
"""
from asm_parser import parse, Reg, Imm, MemRef
import struct
import StringIO

Inst = struct.Struct("BBHI")

MEM_SIZES = {
    'W': 0,
    'H': 1,
    'B': 2,
    'DW': 3,
}

MEM_LOAD_OPS = { 'LDX' + k: (0x61 | (v << 3)) for k, v in MEM_SIZES.items() }
MEM_STORE_IMM_OPS = { 'ST' + k: (0x62 | (v << 3))  for k, v in MEM_SIZES.items() }
MEM_STORE_REG_OPS = { 'STX' + k: (0x63 | (v << 3)) for k, v in MEM_SIZES.items() }

UNARY_ALU_OPS = {
    'NEG': 8,
}

BINARY_ALU_OPS = {
    'ADD': 0,
    'SUB': 1,
    'MUL': 2,
    'DIV': 3,
    'OR': 4,
    'AND': 5,
    'LSH': 6,
    'RSH': 7,
    'MOD': 9,
    'XOR': 10,
    'MOV': 11,
    'ARSH': 12,
}

UNARY_ALU64_OPS = { k + '64': v for k, v in UNARY_ALU_OPS.items() }
BINARY_ALU64_OPS = { k + '64': v for k, v in BINARY_ALU_OPS.items() }

END_OPS = {
    'END16': (0xd4, 16),
    'END32': (0xd4, 32),
    'END64': (0xd4, 64),
    'END64_16': (0xd7, 16),
    'END64_32': (0xd7, 32),
    'END64_64': (0xd7, 64),
}

JMP_CMP_OPS = {
    'JEQ': 1,
    'JGT': 2,
    'JGE': 3,
    'JSET': 4,
    'JNE': 5,
    'JSGT': 6,
    'JSGE': 7,
}

JMP_MISC_OPS = {
    'JA': 0,
    'CALL': 8,
    'EXIT': 9,
}

def pack(opcode, dst, src, offset, imm):
    return Inst.pack(opcode & 0xff, (dst | (src << 4)) & 0xff, offset & 0xffff, imm & 0xffffffff)

def assemble_binop(op, cls, ops, dst, src, offset):
    opcode = cls | (ops[op] << 4)
    if isinstance(src, Imm):
        return pack(opcode, dst.num, 0, offset, src.value)
    else:
        return pack(opcode | 0x08, dst.num, src.num, offset, 0)

def assemble_one(inst):
    op = inst[0]
    if op in MEM_LOAD_OPS:
        opcode = MEM_LOAD_OPS[op]
        return pack(opcode, inst[1].num, inst[2].reg.num, inst[2].offset, 0)
    elif op in MEM_STORE_IMM_OPS:
        opcode = MEM_STORE_IMM_OPS[op]
        return pack(opcode, inst[1].reg.num, 0, inst[1].offset, inst[2].value)
    elif op in MEM_STORE_REG_OPS:
        opcode = MEM_STORE_REG_OPS[op]
        return pack(opcode, inst[1].reg.num, inst[2].num, inst[1].offset, 0)
    elif op in UNARY_ALU_OPS:
        opcode = 0x04 | (UNARY_ALU_OPS[op] << 4)
        return pack(opcode, inst[1].num, 0, 0, 0)
    elif op in UNARY_ALU64_OPS:
        opcode = 0x07 | (UNARY_ALU64_OPS[op] << 4)
        return pack(opcode, inst[1].num, 0, 0, 0)
    elif op in BINARY_ALU_OPS:
        return assemble_binop(op, 0x04, BINARY_ALU_OPS, inst[1], inst[2], 0)
    elif op in BINARY_ALU64_OPS:
        return assemble_binop(op, 0x07, BINARY_ALU64_OPS, inst[1], inst[2], 0)
    elif op in END_OPS:
        opcode, imm = END_OPS[op]
        return pack(opcode, inst[1].num, 0, 0, imm)
    elif op in JMP_CMP_OPS:
        return assemble_binop(op, 0x05, JMP_CMP_OPS, inst[1], inst[2], inst[3])
    elif op in JMP_MISC_OPS:
        opcode = 0x05 | (JMP_MISC_OPS[op] << 4)
        if op == 'JA':
            return pack(opcode, 0, 0, inst[1], 0)
        elif op == 'CALL':
            return pack(opcode, 0, 0, 0, inst[1].value)
        elif op == 'EXIT':
            return pack(opcode, 0, 0, 0, 0)
    else:
        raise ValueError("unexpected instruction %r" % op)

def assemble(source):
    insts = parse(source)
    output = StringIO.StringIO()
    for inst in insts:
        output.write(assemble_one(inst))
    return output.getvalue()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('input', type=argparse.FileType('r'), default='-')
    parser.add_argument('output', type=argparse.FileType('w'), default='-')
    args = parser.parse_args()

    args.output.write(assemble(args.input.read()))
