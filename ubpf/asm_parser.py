#!/usr/bin/env python
from parcon import *
from collections import namedtuple

hexchars = '0123456789abcdefABCDEF'

Reg = namedtuple("Reg", ["num"])
Imm = namedtuple("Imm", ["value"])
MemRef = namedtuple("MemRef", ["reg", "offset"])

def keywords(vs):
    return First(*[Keyword(SignificantLiteral(v)) for v in vs])

hexnum = SignificantLiteral('0x') + +CharIn(hexchars)
decnum = +Digit()
offset = (CharIn("+-") + Exact(hexnum | decnum))[flatten]["".join][lambda x: int(x, 0)]
imm = (-CharIn("+-") + Exact(hexnum | decnum))[flatten]["".join][lambda x: int(x, 0)][Imm]

reg = Literal('r') + integer[int][Reg]
memref = (Literal('[') + reg + Optional(offset, 0) + Literal(']'))[lambda x: MemRef(*x)]

unary_alu_ops = ['NEG', 'NEG64', 'END16', 'END64_16', 'END32', 'END64_32', 'END64', 'END64_64']
binary_alu_ops = ['ADD', 'SUB', 'MUL', 'DIV', 'OR', 'AND', 'LSH', 'RSH',
                  'MOD', 'XOR', 'MOV', 'ARSH']
binary_alu_ops.extend([x + '64' for x in binary_alu_ops])

alu_instruction = \
    (keywords(unary_alu_ops) + reg) | \
    (keywords(binary_alu_ops) + reg + "," + (reg | imm))

mem_sizes = ['W', 'H', 'B', 'DW']
mem_store_reg_ops = ['STX' + s for s in mem_sizes]
mem_store_imm_ops = ['ST' + s for s in mem_sizes]
mem_load_ops = ['LDX' + s for s in mem_sizes]

mem_instruction = \
    (keywords(mem_store_reg_ops) + memref + "," + reg) | \
    (keywords(mem_store_imm_ops) + memref + "," + imm) | \
    (keywords(mem_load_ops) + reg + "," + memref)

jmp_cmp_ops = ['JEQ', 'JGT', 'JGE', 'JSET', 'JNE', 'JSGT', 'JSGE']
jmp_instruction = \
    (keywords(jmp_cmp_ops) + reg + "," + (reg | imm) + "," + offset) | \
    (keywords(['JA']) + offset) | \
    (keywords(['CALL']) + imm) | \
    (keywords(['EXIT'])[lambda x: (x, )])

instruction = alu_instruction | mem_instruction | jmp_instruction

start = ZeroOrMore(instruction + Optional(Literal(';'))) + End()

def parse(source):
    return start.parse_string(source)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Assembly parser", formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('file', type=argparse.FileType('r'), default='-')
    args = parser.parse_args()
    result = parse(args.file.read())
    for inst in result:
        print repr(inst)
