// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "catch.hpp"
#include <boost/dll/runtime_symbol_info.hpp>
#include "../external/bpf_conformance/include/bpf_conformance.h"

#define CONFORMANCE_TEST_PATH "external/bpf_conformance/tests/"

void test_conformance(std::string filename, bpf_conformance_test_result_t expected_result) {
    std::vector<std::filesystem::path> test_files = {CONFORMANCE_TEST_PATH + filename};
    bool list_opcodes_tested = false;
    std::string plugin_options;
    boost::filesystem::path test_path = boost::dll::program_location();
    boost::filesystem::path extension = test_path.extension();
    std::filesystem::path plugin_path =
        test_path.remove_filename().append("conformance_check" + extension.string()).string();
    std::map<std::filesystem::path, std::tuple<bpf_conformance_test_result_t, std::string>> result =
        bpf_conformance(test_files, plugin_path, plugin_options, list_opcodes_tested);
    for (auto file : test_files) {
        auto& [file_result, _] = result[file];
        REQUIRE(file_result == expected_result);
    }
}

#define TEST_CONFORMANCE(filename) \
    TEST_CASE("conformance_check " filename, "[conformance]") { \
        test_conformance(filename, bpf_conformance_test_result_t::TEST_RESULT_PASS); \
    }

// Some tests don't pass yet, but ought to in the future.
#define TEST_CONFORMANCE_FAIL(filename) \
    TEST_CASE("conformance_check " filename, "[conformance]") {  \
        test_conformance(filename, bpf_conformance_test_result_t::TEST_RESULT_FAIL); \
    }

TEST_CONFORMANCE("add.data")
TEST_CONFORMANCE("add64.data")
TEST_CONFORMANCE("alu-arith.data")
TEST_CONFORMANCE("alu-bit.data")
TEST_CONFORMANCE("alu64-arith.data")
TEST_CONFORMANCE_FAIL("alu64-bit.data")
TEST_CONFORMANCE_FAIL("arsh-reg.data")
TEST_CONFORMANCE("arsh.data")
TEST_CONFORMANCE_FAIL("arsh32-high-shift.data")
TEST_CONFORMANCE_FAIL("arsh64.data")
TEST_CONFORMANCE("be16-high.data")
TEST_CONFORMANCE("be16.data")
TEST_CONFORMANCE("be32-high.data")
TEST_CONFORMANCE("be32.data")
TEST_CONFORMANCE("be64.data")
TEST_CONFORMANCE_FAIL("call_unwind_fail.data")
TEST_CONFORMANCE("div-by-zero-reg.data")
TEST_CONFORMANCE("div32-high-divisor.data")
TEST_CONFORMANCE("div32-imm.data")
TEST_CONFORMANCE("div32-reg.data")
TEST_CONFORMANCE("div64-by-zero-reg.data")
TEST_CONFORMANCE("div64-imm.data")
TEST_CONFORMANCE("div64-reg.data")
TEST_CONFORMANCE("exit-not-last.data")
TEST_CONFORMANCE("exit.data")
TEST_CONFORMANCE("jeq-imm.data")
TEST_CONFORMANCE("jeq-reg.data")
TEST_CONFORMANCE("jge-imm.data")
TEST_CONFORMANCE("jgt-imm.data")
TEST_CONFORMANCE("jgt-reg.data")
TEST_CONFORMANCE("jit-bounce.data")
TEST_CONFORMANCE("jle-imm.data")
TEST_CONFORMANCE("jle-reg.data")
TEST_CONFORMANCE("jlt-imm.data")
TEST_CONFORMANCE("jlt-reg.data")
TEST_CONFORMANCE("jne-reg.data")
TEST_CONFORMANCE_FAIL("jset-imm.data")
TEST_CONFORMANCE_FAIL("jset-reg.data")
TEST_CONFORMANCE("jsge-imm.data")
TEST_CONFORMANCE("jsge-reg.data")
TEST_CONFORMANCE("jsgt-imm.data")
TEST_CONFORMANCE("jsgt-reg.data")
TEST_CONFORMANCE("jsle-imm.data")
TEST_CONFORMANCE("jsle-reg.data")
TEST_CONFORMANCE("jslt-imm.data")
TEST_CONFORMANCE("jslt-reg.data")
TEST_CONFORMANCE("lddw.data")
TEST_CONFORMANCE("lddw2.data")
TEST_CONFORMANCE_FAIL("ldxb-all.data")
TEST_CONFORMANCE_FAIL("ldxb.data")
TEST_CONFORMANCE_FAIL("ldxdw.data")
TEST_CONFORMANCE_FAIL("ldxh-all.data")
TEST_CONFORMANCE_FAIL("ldxh-all2.data")
TEST_CONFORMANCE_FAIL("ldxh-same-reg.data")
TEST_CONFORMANCE_FAIL("ldxh.data")
TEST_CONFORMANCE_FAIL("ldxw-all.data")
TEST_CONFORMANCE_FAIL("ldxw.data")
TEST_CONFORMANCE("le16.data")
TEST_CONFORMANCE("le32.data")
TEST_CONFORMANCE("le64.data")
TEST_CONFORMANCE("lsh-reg.data")
TEST_CONFORMANCE_FAIL("mem-len.data")
TEST_CONFORMANCE("mod-by-zero-reg.data")
TEST_CONFORMANCE("mod.data")
TEST_CONFORMANCE("mod32.data")
TEST_CONFORMANCE("mod64-by-zero-reg.data")
TEST_CONFORMANCE_FAIL("mod64.data")
TEST_CONFORMANCE("mov.data")
TEST_CONFORMANCE("mul32-imm.data")
TEST_CONFORMANCE("mul32-reg-overflow.data")
TEST_CONFORMANCE("mul32-reg.data")
TEST_CONFORMANCE("mul64-imm.data")
TEST_CONFORMANCE("mul64-reg.data")
TEST_CONFORMANCE("neg.data")
TEST_CONFORMANCE("neg64.data")
TEST_CONFORMANCE_FAIL("prime.data")
TEST_CONFORMANCE("rsh-reg.data")
TEST_CONFORMANCE("rsh32.data")
TEST_CONFORMANCE_FAIL("stack.data")
TEST_CONFORMANCE("stb.data")
TEST_CONFORMANCE("stdw.data")
TEST_CONFORMANCE("sth.data")
TEST_CONFORMANCE("stw.data")
TEST_CONFORMANCE_FAIL("stxb-all.data")
TEST_CONFORMANCE_FAIL("stxb-all2.data")
TEST_CONFORMANCE_FAIL("stxb-chain.data")
TEST_CONFORMANCE("stxb.data")
TEST_CONFORMANCE_FAIL("stxdw.data")
TEST_CONFORMANCE("stxh.data")
TEST_CONFORMANCE("stxw.data")
TEST_CONFORMANCE_FAIL("subnet.data")
