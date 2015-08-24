#!/usr/bin/env python
"""
eBPF disassembler

Reads the given file or stdin. The input should be raw eBPF
instructions (not an ELF object file).
"""
import struct
import StringIO

Inst = struct.Struct("BBHI")

CLASSES = {
    0: "LD",
    1: "LDX",
    2: "ST",
    3: "STX",
    4: "ALU",
    5: "JMP",
    7: "ALU64",
}

ALU_OPCODES = {
    0: 'ADD',
    1: 'SUB',
    2: 'MUL',
    3: 'DIV',
    4: 'OR',
    5: 'AND',
    6: 'LSH',
    7: 'RSH',
    8: 'NEG',
    9: 'MOD',
    10: 'XOR',
    11: 'MOV',
    12: 'ARSH',
    13: 'END',
}

JMP_OPCODES = {
    0: 'JA',
    1: 'JEQ',
    2: 'JGT',
    3: 'JGE',
    4: 'JSET',
    5: 'JNE',
    6: 'JSGT',
    7: 'JSGE',
    8: 'CALL',
    9: 'EXIT',
}

MODES = {
    0: 'IMM',
    1: 'ABS',
    2: 'IND',
    3: 'MEM',
    6: 'XADD',
}

SIZES = {
    0: 'W',
    1: 'H',
    2: 'B',
    3: 'DW',
}

BPF_CLASS_LD = 0
BPF_CLASS_LDX = 1
BPF_CLASS_ST = 2
BPF_CLASS_STX = 3
BPF_CLASS_ALU = 4
BPF_CLASS_JMP = 5
BPF_CLASS_ALU64 = 7

BPF_ALU_NEG = 8
BPF_ALU_END = 13

def R(reg):
    return "r" + str(reg)

def I(imm):
    return "$%x" % imm

def M(base, off):
    if off != 0:
        return "[%s%s]" % (base, O(off))
    else:
        return "[%s]" % base

def O(off):
    if off <= 32767:
        return "+" + str(off)
    else:
        return "-" + str(65536-off)

def disassemble_one(data, offset):
    code, regs, off, imm = Inst.unpack_from(data, offset)
    dst_reg = regs & 0xf
    src_reg = (regs >> 4) & 0xf
    cls = code & 7

    class_name = CLASSES.get(cls)

    if cls == BPF_CLASS_ALU or cls == BPF_CLASS_ALU64:
        source = (code >> 3) & 1
        opcode = (code >> 4) & 0xf
        opcode_name = ALU_OPCODES.get(opcode)
        if cls == BPF_CLASS_ALU64:
            opcode_name += "64"

        if opcode == BPF_ALU_END and cls == BPF_CLASS_ALU64:
            return "%s_%d %s" % (opcode_name, imm, R(dst_reg))
        elif opcode == BPF_ALU_END:
            return "%s%d %s" % (opcode_name, imm, R(dst_reg))
        elif opcode == BPF_ALU_NEG:
            return "%s %s" % (opcode_name, R(dst_reg))
        elif source == 0:
            return "%s %s, %s" % (opcode_name, R(dst_reg), I(imm))
        else:
            return "%s %s, %s" % (opcode_name, R(dst_reg), R(src_reg))
    elif cls == BPF_CLASS_JMP:
        source = (code >> 3) & 1
        opcode = (code >> 4) & 0xf
        opcode_name = JMP_OPCODES.get(opcode)

        if opcode_name == "EXIT":
            return "EXIT"
        elif opcode_name == "CALL":
            return "%s %s" % (opcode_name, I(imm))
        elif opcode_name == "JA":
            return "%s %s" % (opcode_name, O(off))
        elif source == 0:
            return "%s %s, %s, %s" % (opcode_name, R(dst_reg), I(imm), O(off))
        else:
            return "%s %s, %s, %s" % (opcode_name, R(dst_reg), R(src_reg), O(off))
    elif cls == BPF_CLASS_LD or cls == BPF_CLASS_LDX or cls == BPF_CLASS_ST or cls == BPF_CLASS_STX:
        size = (code >> 3) & 3
        mode = (code >> 5) & 7
        mode_name = MODES.get(mode, str(mode))
        # TODO use different syntax for non-MEM instructions
        size_name = SIZES.get(size, str(size))
        if cls == BPF_CLASS_LD and mode_name == "IMM":
            return "%s %s, %s" % (class_name + size_name, R(dst_reg), I(imm))
        elif cls == BPF_CLASS_LD:
            # Probably not correct
            return "%s %s, %s" % (class_name + size_name, M(R(dst_reg), off), I(imm))
        elif cls == BPF_CLASS_LDX:
            return "%s %s, %s" % (class_name + size_name, R(dst_reg), M(R(src_reg), off))
        elif cls == BPF_CLASS_ST:
            return "%s %s, %s" % (class_name + size_name, M(R(dst_reg), off), I(imm))
        elif cls == BPF_CLASS_STX:
            return "%s %s, %s" % (class_name + size_name, M(R(dst_reg), off), R(src_reg))
    else:
        return "unknown instruction %#x" % code

    offset = 0
    while offset < len(data):
        print disassemble_one(data, offset)
        offset += 8

def disassemble(data):
    output = StringIO.StringIO()
    offset = 0
    while offset < len(data):
        output.write(disassemble_one(data, offset) + "\n")
        offset += 8
    return output.getvalue()
