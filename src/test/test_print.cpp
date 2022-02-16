// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "catch.hpp"

#include <fstream>
#include <regex>
#include <string>
#include <sstream>
#include <variant>

#include "asm_files.hpp"
#include "asm_ostream.hpp"
#include "asm_unmarshal.hpp"

#define TEST_OBJECT_FILE_DIRECTORY "ebpf-samples/build/"
#define TEST_ASM_FILE_DIRECTORY "ebpf-samples/asm/"
#define PRINT_CASE(file) \
    TEST_CASE("Print suite: " #file, "[print]") { \
        verify_printed_string(#file);\
    }

void verify_printed_string(const std::string file)
{
    std::stringstream generated_output;
    auto raw_progs = read_elf(std::string(TEST_OBJECT_FILE_DIRECTORY) + file + ".o", "", nullptr, &g_ebpf_platform_linux);
    raw_program raw_prog = raw_progs.back();
    std::variant<InstructionSeq, std::string> prog_or_error = unmarshal(raw_prog);
    REQUIRE(std::holds_alternative<InstructionSeq>(prog_or_error));
    auto& prog = std::get<InstructionSeq>(prog_or_error);
    std::string current_directory = get_current_dir_name();
    print(prog, generated_output, {});
    std::ifstream input(std::string(TEST_ASM_FILE_DIRECTORY) + file + std::string(".asm"));
    REQUIRE(input);
    std::string line;
    std::string expected_output;
    std::string output = generated_output.str();
    while (std::getline(input, line))
    {
        expected_output += line;
        expected_output += "\n";
    }
    output = std::regex_replace(output, std::regex(current_directory), ".");
    REQUIRE(expected_output == output);
}


PRINT_CASE(byteswap)
PRINT_CASE(ctxoffset)
PRINT_CASE(exposeptr)
PRINT_CASE(exposeptr2)
PRINT_CASE(map_in_map)
PRINT_CASE(mapoverflow)
PRINT_CASE(mapunderflow)
PRINT_CASE(mapvalue-overrun)
PRINT_CASE(nullmapref)
PRINT_CASE(packet_access)
PRINT_CASE(packet_overflow)
PRINT_CASE(packet_reallocate)
PRINT_CASE(packet_start_ok)
PRINT_CASE(stackok)
PRINT_CASE(tail_call)
PRINT_CASE(tail_call_bad)
PRINT_CASE(twomaps)
PRINT_CASE(twostackvars)
PRINT_CASE(twotypes)
