#!/usr/bin/env python
"""
Expand testcase into individual files
"""
import os
import sys
import struct
import testdata
import argparse

ROOT_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")
if os.path.exists(os.path.join(ROOT_DIR, "ubpf")):
    # Running from source tree
    sys.path.insert(0, ROOT_DIR)

import ubpf.assembler
import ubpf.disassembler

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('name')
    parser.add_argument('path')
    args = parser.parse_args()

    data = testdata.read(args.name + '.data')
    assert data

    if not os.path.isdir(args.path):
        os.makedirs(args.path)

    def writefile(name, contents):
        file("%s/%s" % (args.path, name), "w").write(contents)

    if 'mem' in data:
        writefile('mem', data['mem'])

    if 'raw' in data:
        code = ''.join(struct.pack("=Q", x) for x in data['raw'])
    elif 'asm' in data:
        code = ubpf.assembler.assemble(data['asm'])
    else:
        code = None

    if code:
        writefile('code', code)

    if 'asm' in data:
        writefile('asm', data['asm'])
    else:
        writefile('asm', ubpf.disassembler.disassemble(code))

if __name__ == "__main__":
    main()
