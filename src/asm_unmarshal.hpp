// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <istream>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "asm_syntax.hpp"
#include "spec_type_descriptors.hpp"
#include "platform.hpp"

/** Translate a sequence of eBPF instructions (elf binary format) to a sequence
 *  of Instructions.
 *
 *  \param raw_prog is the input program to parse.
 *  \param notes is where errors and warnings are written to.
 *  \return a sequence of instruction if successful, an error string otherwise.
 */
std::variant<InstructionSeq, std::string> unmarshal(const raw_program& raw_prog, std::vector<std::vector<std::string>>& notes);
std::variant<InstructionSeq, std::string> unmarshal(const raw_program& raw_prog);
Call make_call(int func, const ebpf_platform_t& platform);
