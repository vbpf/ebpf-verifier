// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "asm_syntax.hpp"
#include "ebpf_vm_isa.hpp"
#include <vector>

std::vector<ebpf_inst> marshal(const Instruction& ins, pc_t pc);
// TODO marshal to ostream?
