import unittest
import struct
import ubpf.disassembler

class DisassemblerTests(unittest.TestCase):
    def check(self, inst, expected):
        data = struct.pack("L", inst)
        self.assertEquals(expected, ubpf.disassembler.disassemble_one(data, 0))

    def test_alu(self):
        self.check(0x0000000200000104, "add r1, 0x2")
        self.check(0xffffffff00000904, "add r9, 0xffffffff")
        self.check(0x000000000000210c, "add r1, r2")
        self.check(0x000000000000211c, "sub r1, r2")
        self.check(0x000000000000212c, "mul r1, r2")
        self.check(0x000000000000213c, "div r1, r2")
        self.check(0x000000000000214c, "or r1, r2")
        self.check(0x000000000000215c, "and r1, r2")
        self.check(0x000000000000216c, "lsh r1, r2")
        self.check(0x000000000000217c, "rsh r1, r2")
        self.check(0x000000000000018c, "neg r1")
        self.check(0x000000000000219c, "mod r1, r2")
        self.check(0x00000000000021ac, "xor r1, r2")
        self.check(0x00000000000021bc, "mov r1, r2")
        self.check(0x00000000000021cc, "arsh r1, r2")
        self.check(0x00000010000001d4, "end16 r1")
        self.check(0x00000020000001d4, "end32 r1")
        self.check(0x00000040000001d4, "end64 r1")

    def test_alu64(self):
        self.check(0x0000000200000107, "add64 r1, 0x2")
        self.check(0xffffffff00000907, "add64 r9, 0xffffffff")
        self.check(0x000000000000210f, "add64 r1, r2")
        self.check(0x000000000000211f, "sub64 r1, r2")
        self.check(0x000000000000212f, "mul64 r1, r2")
        self.check(0x000000000000213f, "div64 r1, r2")
        self.check(0x000000000000214f, "or64 r1, r2")
        self.check(0x000000000000215f, "and64 r1, r2")
        self.check(0x000000000000216f, "lsh64 r1, r2")
        self.check(0x000000000000217f, "rsh64 r1, r2")
        self.check(0x000000000000018f, "neg64 r1")
        self.check(0x000000000000219f, "mod64 r1, r2")
        self.check(0x00000000000021af, "xor64 r1, r2")
        self.check(0x00000000000021bf, "mov64 r1, r2")
        self.check(0x00000000000021cf, "arsh64 r1, r2")
        self.check(0x00000010000001d7, "end64_16 r1")
        self.check(0x00000020000001d7, "end64_32 r1")
        self.check(0x00000040000001d7, "end64_64 r1")

    def test_jmp(self):
        self.check(0x0000000000010005, "ja +1")
        self.check(0x000000007fff0005, "ja +32767")
        self.check(0x00000000ffff0005, "ja -1")
        self.check(0x0000000080000005, "ja -32768")
        self.check(0x0000003300010115, "jeq r1, 0x33, +1")
        self.check(0x000000000001211d, "jeq r1, r2, +1")
        self.check(0x000000000001212d, "jgt r1, r2, +1")
        self.check(0x000000000001213d, "jge r1, r2, +1")
        self.check(0x000000000001214d, "jset r1, r2, +1")
        self.check(0x000000000001215d, "jne r1, r2, +1")
        self.check(0x000000000001216d, "jsgt r1, r2, +1")
        self.check(0x000000000001217d, "jsge r1, r2, +1")
        self.check(0x0000000100000085, "call 0x1")
        self.check(0x0000000000000095, "exit")

    # TODO test ld

    def test_ldx(self):
        self.check(0x0000000000002161, "ldxw r1, [r2]")
        self.check(0x0000000000002169, "ldxh r1, [r2]")
        self.check(0x0000000000002171, "ldxb r1, [r2]")
        self.check(0x0000000000002179, "ldxdw r1, [r2]")
        self.check(0x0000000000012161, "ldxw r1, [r2+1]")
        self.check(0x000000007fff2161, "ldxw r1, [r2+32767]")
        self.check(0x00000000ffff2161, "ldxw r1, [r2-1]")
        self.check(0x0000000080002161, "ldxw r1, [r2-32768]")

    def test_st(self):
        self.check(0x0000003300000162, "stw [r1], 0x33")
        self.check(0x0000003300010162, "stw [r1+1], 0x33")
        self.check(0x000000337fff0162, "stw [r1+32767], 0x33")
        self.check(0x00000033ffff0162, "stw [r1-1], 0x33")
        self.check(0x0000003380000162, "stw [r1-32768], 0x33")

    def test_stx(self):
        self.check(0x0000000000002163, "stxw [r1], r2")
        self.check(0x0000000000012163, "stxw [r1+1], r2")
        self.check(0x000000007fff2163, "stxw [r1+32767], r2")
        self.check(0x00000000ffff2163, "stxw [r1-1], r2")
        self.check(0x0000000080002163, "stxw [r1-32768], r2")
