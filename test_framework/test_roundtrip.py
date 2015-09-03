import struct
import difflib
from nose.plugins.skip import Skip, SkipTest
import ubpf.assembler
import ubpf.disassembler
import testdata

# Just for assertion messages
def try_disassemble(inst):
    data = struct.pack("=Q", inst)
    try:
        return ubpf.disassembler.disassemble(data).strip()
    except ValueError:
        return "<error>"

def check_datafile(filename):
    """
    Verify that the reassembling the output of the disassembler produces
    the same binary, and that disassembling the output of the assembler
    produces the same text.
    """
    data = testdata.read(filename)

    if 'asm' not in data:
        raise SkipTest("no asm section in datafile")

    assembled = ubpf.assembler.assemble(data['asm'])
    disassembled = ubpf.disassembler.disassemble(assembled)
    reassembled = ubpf.assembler.assemble(disassembled)
    disassembled2 = ubpf.disassembler.disassemble(reassembled)

    if disassembled != disassembled2:
        diff = difflib.unified_diff(disassembled.splitlines(), disassembled2.splitlines(), lineterm="")
        formatted = ''.join('  %s\n' % x for x in diff)
        raise AssertionError("Assembly differs:\n%s" % formatted)

    if assembled != reassembled:
        raise AssertionError("binary differs")

def test_datafiles():
    # Nose test generator
    # Creates a testcase for each datafile
    for filename in testdata.list_files():
        yield check_datafile, filename
