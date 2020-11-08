#pragma once

#include "asm_syntax.hpp"
#include "linux_ebpf.hpp"
#include <vector>

std::vector<ebpf_inst> marshal(const Instruction& ins, pc_t pc);
// TODO marshal to ostream?
