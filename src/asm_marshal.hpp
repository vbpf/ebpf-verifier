#pragma once

#include "asm_syntax.hpp"
#include "linux_ebpf.hpp"
#include <vector>

std::vector<ebpf_inst> marshal(Instruction ins, pc_t pc);
std::vector<ebpf_inst> marshal(std::vector<Instruction> insts);
std::vector<ebpf_inst> marshal(InstructionSeq insts);
// TODO marshal to ostream?
