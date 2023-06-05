// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <catch2/catch_all.hpp>

#include <map>
#include <string>
#include <vector>

#include <boost/algorithm/string/trim.hpp>

#if !defined(MAX_PATH)
#define MAX_PATH (256)
#endif

#include "btf_parser.h"
#include "elfio/elfio.hpp"

#define TEST_OBJECT_FILE_DIRECTORY "ebpf-samples/build/"
#define TEST_JSON_FILE_DIRECTORY "ebpf-samples/json/"
#define BTF_CASE(file) \
    TEST_CASE("BTF suite: " #file, "[BTF]") { \
        verify_BTF_json(#file);\
    }

void verify_BTF_json(const std::string& file)
{
    std::stringstream generated_output;
    auto reader = ELFIO::elfio();
    REQUIRE(reader.load(std::string(TEST_OBJECT_FILE_DIRECTORY) + file + ".o"));

    auto btf = reader.sections[".BTF"];

    btf_type_data btf_data = std::vector<uint8_t>({btf->get_data(), btf->get_data() + btf->get_size()});

    btf_data.to_json(generated_output);

    // Pretty print the JSON output.
    std::string pretty_printed_json = pretty_print_json(generated_output.str());

    // Read the expected output from the .json file.
    std::ifstream expected_stream(std::string(TEST_JSON_FILE_DIRECTORY) + file + std::string(".json"));
    std::stringstream genereated_stream(pretty_printed_json);

    // Compare each line of the expected output with the actual output.
    std::string expected_line;
    std::string actual_line;
    while (std::getline(expected_stream, expected_line)) {
        bool has_more = (bool)std::getline(genereated_stream, actual_line);
        REQUIRE(has_more);
        boost::algorithm::trim_right(expected_line);
        boost::algorithm::trim_right(actual_line);
        REQUIRE(expected_line == actual_line);
    }
    bool has_more = (bool)std::getline(expected_stream, actual_line);
    REQUIRE_FALSE(has_more);
}


BTF_CASE(byteswap)
BTF_CASE(ctxoffset)
BTF_CASE(exposeptr)
BTF_CASE(exposeptr2)
BTF_CASE(map_in_map)
BTF_CASE(mapoverflow)
BTF_CASE(mapunderflow)
BTF_CASE(mapvalue-overrun)
BTF_CASE(nullmapref)
BTF_CASE(packet_access)
BTF_CASE(packet_overflow)
BTF_CASE(packet_reallocate)
BTF_CASE(packet_start_ok)
BTF_CASE(stackok)
BTF_CASE(tail_call)
BTF_CASE(tail_call_bad)
BTF_CASE(twomaps)
BTF_CASE(twostackvars)
BTF_CASE(twotypes)
