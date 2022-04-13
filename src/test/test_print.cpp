// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "catch.hpp"

#include <string>
#include <variant>

#include <boost/algorithm/string/trim.hpp>

#if !defined(MAX_PATH)
#define MAX_PATH (256)
#endif

#include "asm_files.hpp"
#include "asm_ostream.hpp"
#include "asm_unmarshal.hpp"

#define TEST_OBJECT_FILE_DIRECTORY "ebpf-samples/build/"
#define TEST_ASM_FILE_DIRECTORY "ebpf-samples/asm/"
#define PRINT_CASE(file) \
    TEST_CASE("Print suite: " #file, "[print]") { \
        verify_printed_string(#file);\
    }

void verify_printed_string(const std::string& file)
{
    std::stringstream generated_output;
    auto raw_progs = read_elf(std::string(TEST_OBJECT_FILE_DIRECTORY) + file + ".o", "", nullptr, &g_ebpf_platform_linux);
    raw_program raw_prog = raw_progs.back();
    std::variant<InstructionSeq, std::string> prog_or_error = unmarshal(raw_prog);
    REQUIRE(std::holds_alternative<InstructionSeq>(prog_or_error));
    auto& program = std::get<InstructionSeq>(prog_or_error);
    print(program, generated_output, {}, true);
    std::ifstream expected_stream(std::string(TEST_ASM_FILE_DIRECTORY) + file + std::string(".asm"));
    REQUIRE(expected_stream);
    std::string expected_line;
    std::string actual_line;
    while (std::getline(expected_stream, expected_line)) {
        bool has_more = (bool)std::getline(generated_output, actual_line);
        REQUIRE(has_more);
        boost::algorithm::trim_right(expected_line);
        boost::algorithm::trim_right(actual_line);
        REQUIRE(expected_line == actual_line);
    }
    bool has_more = (bool)std::getline(expected_stream, actual_line);
    REQUIRE_FALSE(has_more);
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
