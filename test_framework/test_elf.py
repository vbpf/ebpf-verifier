import sys
import os
import tempfile
import struct
import re
import elftools.elf.structs
from subprocess import Popen, PIPE
from nose.plugins.skip import Skip, SkipTest
from elftools.construct import Container
from elftools.elf.constants import SH_FLAGS
import testdata
VM = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "vm", "test")

def template():
    parts = {}
    parts['order'] = []
    def add(name, value):
        parts[name] = value
        parts['order'].append(name)

    add('ehdr', Container(
        e_ident=Container(
            EI_MAG=[0x7f, ord('E'), ord('L'), ord('F')],
            EI_CLASS='ELFCLASS64',
            EI_DATA='ELFDATA2LSB',
            EI_VERSION='EV_CURRENT',
            EI_OSABI='ELFOSABI_SYSV',
            EI_ABIVERSION=0),
        e_type='ET_REL',
        e_machine='EM_NONE',
        e_version=0,
        e_entry=0,
        e_phoff=0,
        e_shoff=64,
        e_flags=0,
        e_ehsize=64,
        e_phentsize=0,
        e_phnum=0,
        e_shentsize=64,
        e_shnum=4,
        e_shstrndx=2))

    add('first_shdr', Container(
        sh_name=0,
        sh_type='SHT_NULL',
        sh_flags=0,
        sh_addr=0,
        sh_offset=0,
        sh_size=0,
        sh_link=0,
        sh_info=0,
        sh_addralign=0,
        sh_entsize=0))

    add('text_shdr', Container(
        sh_name=1,
        sh_type='SHT_PROGBITS',
        sh_flags=SH_FLAGS.SHF_ALLOC|SH_FLAGS.SHF_EXECINSTR,
        sh_addr=0,
        sh_offset=320,
        sh_size=16,
        sh_link=0,
        sh_info=0,
        sh_addralign=8,
        sh_entsize=0))

    add('strtab_shdr', Container(
        sh_name=7,
        sh_type='SHT_STRTAB',
        sh_flags=0,
        sh_addr=0,
        sh_offset=336,
        sh_size=23,
        sh_link=0,
        sh_info=0,
        sh_addralign=1,
        sh_entsize=0))

    add('symtab_shdr', Container(
        sh_name=15,
        sh_type='SHT_SYMTAB',
        sh_flags=0,
        sh_addr=0,
        sh_offset=359,
        sh_size=0,
        sh_link=0,
        sh_info=0,
        sh_addralign=8,
        sh_entsize=24))

    add("text", "\xb7\x00\x00\x00\x2a\x00\x00\x00\x95\x00\x00\x00\x00\x00\x00\x00")
    add("strtab", "\0.text\0.strtab\0.symtab\0")
    add("symtab", "")

    return parts

def serialize(parts):
    s = elftools.elf.structs.ELFStructs(elfclass=64)
    tmp = []

    for name in parts['order']:
        part = parts[name]
        serializer = str
        if name == 'ehdr':
            serializer = s.Elf_Ehdr.build
        elif name.endswith('shdr'):
            serializer = s.Elf_Shdr.build
        tmp.append(serializer(part))

    return ''.join(tmp)

def check_datafile(filename):
    """
    """
    data = testdata.read(filename)
    if 'pyelf' not in data:
        raise SkipTest("no pyelf section in datafile")
    if 'result' not in data and 'error' not in data and 'error pattern' not in data:
        raise SkipTest("no result or error section in datafile")
    if not os.path.exists(VM):
        raise SkipTest("VM not found")

    parts = template()
    exec(data['pyelf'], parts)
    elf = serialize(parts)

    cmd = [VM]

    cmd.append('-')

    vm = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    stdout, stderr = vm.communicate(elf)
    stderr = stderr.strip()

    if 'error' in data:
        if data['error'] != stderr:
            raise AssertionError("Expected error %r, got %r" % (data['error'], stderr))
    elif 'error pattern' in data:
        if not re.search(data['error pattern'], stderr):
            raise AssertionError("Expected error matching %r, got %r" % (data['error pattern'], stderr))
    else:
        if stderr:
            raise AssertionError("Unexpected error %r" % stderr)

    if 'result' in data:
        if vm.returncode != 0:
            raise AssertionError("VM exited with status %d, stderr=%r" % (vm.returncode, stderr))
        expected = int(data['result'], 0)
        result = int(stdout, 0)
        if expected != result:
            raise AssertionError("Expected result 0x%x, got 0x%x, stderr=%r" % (expected, result, stderr))
    else:
        if vm.returncode == 0:
            raise AssertionError("Expected VM to exit with an error code")

def test_datafiles():
    # Nose test generator
    # Creates a testcase for each datafile
    for filename in testdata.list_files():
        yield check_datafile, filename
