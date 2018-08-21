import struct
import StringIO

Inst = struct.Struct("BBHI")

CLASSES = {
    0: "ld",
    1: "ldx",
    2: "st",
    3: "stx",
    4: "alu",
    5: "jmp",
    7: "alu64",
}

ALU_OPCODES = {
    0: 'add',
    1: 'sub',
    2: 'mul',
    3: 'div',
    4: 'or',
    5: 'and',
    6: 'lsh',
    7: 'rsh',
    8: 'neg',
    9: 'mod',
    10: 'xor',
    11: 'mov',
    12: 'arsh',
    13: '(endian)',
}

JMP_OPCODES = {
    0: 'ja',
    1: 'jeq',
    2: 'jgt',
    3: 'jge',
    4: 'jset',
    5: 'jne',
    6: 'jsgt',
    7: 'jsge',
    8: 'call',
    9: 'exit',
    10: 'jlt',
    11: 'jle',
    12: 'jslt',
    13: 'jsle',
}

MODES = {
    0: 'imm',
    1: 'abs',
    2: 'ind',
    3: 'mem',
    6: 'xadd',
}

SIZES = {
    0: 'w',
    1: 'h',
    2: 'b',
    3: 'dw',
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
    return "%#x" % imm

def S(imm):
    return repr(''.join(chr((imm >> i) & 0xff) for i in range(0, 4*(len(I(imm))-2), 8)))

def M(base, off):
    if off != 0:
        return "[%s%+d]" % (base, O(off))
    else:
        return "[%s]" % base

def O(off):
    return off if off <= 32767 else off-65536

def jump_target(off, offset):
    return O(off) + (offset / 8) + 1

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
        if cls == BPF_CLASS_ALU:
            opcode_name += "32"

        if opcode == BPF_ALU_END:
            opcode_name = source == 1 and "be" or "le"
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

        if opcode_name == "exit":
            return opcode_name
        elif opcode_name == "call":
            return "%s %s [%s]" % (opcode_name, I(imm), functions[imm])
        elif opcode_name == "ja":
            return "%s %s" % (opcode_name, jump_target(off, offset))
        elif source == 0:
            return "%s %s, %s, %s" % (opcode_name, R(dst_reg), I(imm), jump_target(off, offset))
        else:
            return "%s %s, %s, %s" % (opcode_name, R(dst_reg), R(src_reg), jump_target(off, offset))
    elif cls == BPF_CLASS_LD or cls == BPF_CLASS_LDX or cls == BPF_CLASS_ST or cls == BPF_CLASS_STX:
        size = (code >> 3) & 3
        mode = (code >> 5) & 7
        mode_name = MODES.get(mode, str(mode))
        # TODO use different syntax for non-MEM instructions
        size_name = SIZES.get(size, str(size))
        if code == 0x18: # lddw
            _, _, _, imm2 = Inst.unpack_from(data, offset+8)
            imm = (imm2 << 32) | imm
            if src_reg == 1:
                return "ldmapfd %s, %s" % (R(dst_reg), I(imm))
            return "%s %s, %s [%s]" % (class_name + size_name, R(dst_reg), I(imm), S(imm))
        elif code == 0x00:
            # Second instruction of lddw
            return None
        elif cls == BPF_CLASS_LD:
            if mode == 3 or mode == 0 or mode == 2:
                return "%s %s, %s" % (class_name + mode_name + size_name, R(dst_reg), M(R(src_reg), off))
            if mode == 1:
                return "%s %s" % (class_name + mode_name + size_name, I(imm))
            assert False, mode_name
        elif cls == BPF_CLASS_LDX:
            if mode == 0 or mode == 3 or mode == 2:
                return "%s %s, %s" % (class_name + size_name, R(dst_reg), M(R(src_reg), off))
            if mode == 1:
                return "%s %s" % (class_name + mode_name + size_name, I(imm))
            assert False, mode_name
        elif cls == BPF_CLASS_ST:
            return "%s %s, %s" % (class_name + size_name, M(R(dst_reg), off), I(imm))
        elif cls == BPF_CLASS_STX:
            if mode_name == 'xadd':
                return "%s %s, %s" % (class_name + mode_name + size_name, M(R(dst_reg), off), R(src_reg))
            return "%s %s, %s" % (class_name + size_name, M(R(dst_reg), off), R(src_reg))
        else:
            return "unknown mem instruction %#x" % code
    else:
        return "unknown instruction %#x" % code

functions = [
	'unspec',
	'map_lookup_elem',
	'map_update_elem',
	'map_delete_elem',
	'probe_read',
	'ktime_get_ns',
	'trace_printk',
	'get_prandom_u32',
	'get_smp_processor_id',
	'skb_store_bytes',
	'l3_csum_replace',
	'l4_csum_replace',
	'tail_call',
	'clone_redirect',
	'get_current_pid_tgid',
	'get_current_uid_gid',
	'get_current_comm',
	'get_cgroup_classid',
	'skb_vlan_push',
	'skb_vlan_pop',
	'skb_get_tunnel_key',
	'skb_set_tunnel_key',
	'perf_event_read',
	'redirect',
	'get_route_realm',
	'perf_event_output',
	'skb_load_bytes',
	'get_stackid',
	'csum_diff',
	'skb_get_tunnel_opt',
	'skb_set_tunnel_opt',
	'skb_change_proto',
	'skb_change_type',
	'skb_under_cgroup',
	'get_hash_recalc',
	'get_current_task',
	'probe_write_user',
	'current_task_under_cgroup',
	'skb_change_tail',
	'skb_pull_data',
	'csum_update',
	'set_hash_invalid',
	'get_numa_node_id',
	'skb_change_head',
	'xdp_adjust_head',
	'probe_read_str',
	'get_socket_cookie',
	'get_socket_uid',
	'set_hash',
	'setsockopt',
	'skb_adjust_room',
	'redirect',
	'sk_redirect_map',
	'sock_map_update',
	'xdp_adjust_meta',
	'perf_event_read_value',
	'perf_prog_read_value',
	'getsockopt',
	'override_return',
	'sock_ops_cb_flags_set',
	'msg_redirect_map',
	'msg_apply_bytes',
	'msg_cork_bytes',
	'msg_pull_data',
	'bind',
	'xdp_adjust_tail',
	'skb_get_xfrm_state',
	'get_stack',
	'skb_load_bytes_relative',
	'xdp_fib_lookup',
	'sock_hash_update',
	'msg_redirect_hash',
	'sk_redirect_hash',
	'lwt_push_encap',
	'lwt_seg6_store_bytes',
	'lwt_seg6_adjust_srh',
	'lwt_seg6_action',
	'rc_repeat',
	'rc_keydown',
	'skb_cgroup_id',
	'get_current_cgroup_id',
]

def disassemble(data):
    output = StringIO.StringIO()
    offset = 0
    pc = 0
    while offset < len(data):
        s = disassemble_one(data, offset)
        if s:
            output.write("%4d: %s\n" % (pc, s))
        pc += 1
        offset += 8
    return output.getvalue()
