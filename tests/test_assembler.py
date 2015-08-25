import struct
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
    Verify that the result of assembling the 'asm' section matches the
    'raw' section.
    """
    data = testdata.read(filename)
    if 'asm' not in data:
        raise SkipTest("no asm section in datafile")
    if 'raw' not in data:
        raise SkipTest("no raw section in datafile")

    bin_result = ubpf.assembler.assemble(data['asm'])
    assert len(bin_result) % 8 == 0
    assert len(bin_result) / 8 == len(data['raw'])

    for i in xrange(0, len(bin_result), 8):
        j = i/8
        inst, = struct.unpack_from("=Q", bin_result[i:i+8])
        exp = data['raw'][j]
        if exp != inst:
            raise AssertionError("Expected instruction %d to be %#x (%s), but was %#x (%s)" %
                (j, exp, try_disassemble(exp), inst, try_disassemble(inst)))

def test_datafiles():
    # Nose test generator
    # Creates a testcase for each datafile
    for filename in testdata.list_files():
        yield check_datafile, filename
