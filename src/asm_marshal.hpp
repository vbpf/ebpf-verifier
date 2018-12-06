#pragma once

#include <vector>
#include "linux_ebpf.hpp"
#include "asm_syntax.hpp"

std::vector<ebpf_inst> marshal(Instruction ins, pc_t pc);
std::vector<ebpf_inst> marshal(std::vector<Instruction> insts);
std::vector<ebpf_inst> marshal(InstructionSeq insts);
// TODO marshal to ostream?
