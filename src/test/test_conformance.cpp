// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "catch.hpp"
#include <boost/dll/runtime_symbol_info.hpp>
#include "../external/bpf_conformance/include/bpf_conformance.h"

#define CONFORMANCE_TEST_PATH "external/bpf_conformance/tests/"

void test_conformance(std::string filename, bpf_conformance_test_result_t expected_result, std::string expected_reason) {
    std::vector<std::filesystem::path> test_files = {CONFORMANCE_TEST_PATH + filename};
    boost::filesystem::path test_path = boost::dll::program_location();
    boost::filesystem::path extension = test_path.extension();
    std::filesystem::path plugin_path =
        test_path.remove_filename().append("conformance_check" + extension.string()).string();
    std::map<std::filesystem::path, std::tuple<bpf_conformance_test_result_t, std::string>> result =
        bpf_conformance(test_files, plugin_path, {}, {}, {}, bpf_conformance_test_CPU_version_t::v3,
                        bpf_conformance_list_instructions_t::LIST_INSTRUCTIONS_NONE, true);
    for (auto file : test_files) {
        auto& [file_result, reason] = result[file];
        REQUIRE(file_result == expected_result);
        if (file_result != bpf_conformance_test_result_t::TEST_RESULT_PASS && !expected_reason.empty()) {
            reason.erase(reason.find_last_not_of(" \n\r\t") + 1); // Remove trailing whitespace.
            REQUIRE(reason == "Plugin returned error code 1 and output " + expected_reason);
        }
    }
}

#define TEST_CONFORMANCE(filename) \
    TEST_CASE("conformance_check " filename, "[conformance]") { \
        test_conformance(filename, bpf_conformance_test_result_t::TEST_RESULT_PASS, {}); \
    }

// Any tests that fail verification are safe, but might prevent
// legitimate programs from being usable.
#define TEST_CONFORMANCE_VERIFICATION_FAILED(filename) \
    TEST_CASE("conformance_check " filename, "[conformance]") { \
        test_conformance(filename, bpf_conformance_test_result_t::TEST_RESULT_FAIL, "Verification failed"); \
    }

// Any tests that return top are safe, but are not as precise as they
// could be and so may prevent legitimate programs from being usable.
#define TEST_CONFORMANCE_TOP(filename) \
    TEST_CASE("conformance_check " filename, "[conformance]") { \
        test_conformance(filename, bpf_conformance_test_result_t::TEST_RESULT_FAIL, "Couldn't determine r0 value"); \
    }

// Any tests that return a range are safe, but are not as precise as they
// could be and so may prevent legitimate programs from being usable.
#define TEST_CONFORMANCE_RANGE(filename, range)                                                                  \
    TEST_CASE("conformance_check " filename, "[conformance]") {                                                  \
        test_conformance(filename, bpf_conformance_test_result_t::TEST_RESULT_FAIL, "r0 value is range " range); \
    }

TEST_CONFORMANCE("add.data")
TEST_CONFORMANCE("add64.data")
TEST_CONFORMANCE("alu-arith.data")
TEST_CONFORMANCE("alu-bit.data")
TEST_CONFORMANCE("alu64-arith.data")
TEST_CONFORMANCE_TOP("alu64-bit.data")
TEST_CONFORMANCE("arsh-reg.data")
TEST_CONFORMANCE("arsh.data")
TEST_CONFORMANCE("arsh32-high-shift.data")
TEST_CONFORMANCE_TOP("arsh64.data")
TEST_CONFORMANCE("be16-high.data")
TEST_CONFORMANCE("be16.data")
TEST_CONFORMANCE("be32-high.data")
TEST_CONFORMANCE("be32.data")
TEST_CONFORMANCE("be64.data")
TEST_CONFORMANCE("call_unwind_fail.data")
TEST_CONFORMANCE("div-by-zero-reg.data")
TEST_CONFORMANCE("div32-high-divisor.data")
TEST_CONFORMANCE("div32-imm.data")
TEST_CONFORMANCE("div32-reg.data")
TEST_CONFORMANCE("div64-by-zero-reg.data")
TEST_CONFORMANCE("div64-imm.data")
TEST_CONFORMANCE("div64-negative-imm.data")
TEST_CONFORMANCE("div64-negative-reg.data")
TEST_CONFORMANCE("div64-reg.data")
TEST_CONFORMANCE("exit-not-last.data")
TEST_CONFORMANCE("exit.data")
TEST_CONFORMANCE("jeq-imm.data")
TEST_CONFORMANCE("jeq-reg.data")
TEST_CONFORMANCE("jeq32-imm.data")
TEST_CONFORMANCE("jeq32-reg.data")
TEST_CONFORMANCE("jge-imm.data")
TEST_CONFORMANCE("jge32-imm.data")
TEST_CONFORMANCE("jge32-reg.data")
TEST_CONFORMANCE("jgt-imm.data")
TEST_CONFORMANCE("jgt-reg.data")
TEST_CONFORMANCE("jgt32-imm.data")
TEST_CONFORMANCE("jgt32-reg.data")
TEST_CONFORMANCE("jit-bounce.data")
TEST_CONFORMANCE("jle-imm.data")
TEST_CONFORMANCE("jle-reg.data")
TEST_CONFORMANCE("jle32-imm.data")
TEST_CONFORMANCE("jle32-reg.data")
TEST_CONFORMANCE("jlt-imm.data")
TEST_CONFORMANCE("jlt-reg.data")
TEST_CONFORMANCE("jlt32-imm.data")
TEST_CONFORMANCE("jlt32-reg.data")
TEST_CONFORMANCE("jne-reg.data")
TEST_CONFORMANCE("jne32-imm.data")
TEST_CONFORMANCE("jne32-reg.data")
TEST_CONFORMANCE("jset-imm.data")
TEST_CONFORMANCE("jset-reg.data")
TEST_CONFORMANCE("jset32-imm.data")
TEST_CONFORMANCE("jset32-reg.data")
TEST_CONFORMANCE("jsge-imm.data")
TEST_CONFORMANCE("jsge-reg.data")
TEST_CONFORMANCE("jsge32-imm.data")
TEST_CONFORMANCE("jsge32-reg.data")
TEST_CONFORMANCE("jsgt-imm.data")
TEST_CONFORMANCE("jsgt-reg.data")
TEST_CONFORMANCE("jsgt32-imm.data")
TEST_CONFORMANCE("jsgt32-reg.data")
TEST_CONFORMANCE("jsle-imm.data")
TEST_CONFORMANCE("jsle-reg.data")
TEST_CONFORMANCE("jsle32-imm.data")
TEST_CONFORMANCE("jsle32-reg.data")
TEST_CONFORMANCE("jslt-imm.data")
TEST_CONFORMANCE("jslt-reg.data")
TEST_CONFORMANCE("jslt32-imm.data")
TEST_CONFORMANCE("jslt32-reg.data")
TEST_CONFORMANCE("lddw.data")
TEST_CONFORMANCE("lddw2.data")
TEST_CONFORMANCE_TOP("ldxb-all.data")
TEST_CONFORMANCE_VERIFICATION_FAILED("ldxb.data")
TEST_CONFORMANCE_VERIFICATION_FAILED("ldxdw.data")
TEST_CONFORMANCE_TOP("ldxh-all.data")
TEST_CONFORMANCE_TOP("ldxh-all2.data")
TEST_CONFORMANCE_TOP("ldxh-same-reg.data")
TEST_CONFORMANCE_VERIFICATION_FAILED("ldxh.data")
TEST_CONFORMANCE_TOP("ldxw-all.data")
TEST_CONFORMANCE_VERIFICATION_FAILED("ldxw.data")
TEST_CONFORMANCE("le16.data")
TEST_CONFORMANCE("le32.data")
TEST_CONFORMANCE("le64.data")
TEST_CONFORMANCE_VERIFICATION_FAILED("lock_add.data")
TEST_CONFORMANCE_VERIFICATION_FAILED("lock_add32.data")
TEST_CONFORMANCE_VERIFICATION_FAILED("lock_and.data")
TEST_CONFORMANCE_VERIFICATION_FAILED("lock_and32.data")
TEST_CONFORMANCE_VERIFICATION_FAILED("lock_cmpxchg.data")
TEST_CONFORMANCE_VERIFICATION_FAILED("lock_cmpxchg32.data")
TEST_CONFORMANCE_VERIFICATION_FAILED("lock_or.data")
TEST_CONFORMANCE_VERIFICATION_FAILED("lock_or32.data")
TEST_CONFORMANCE_VERIFICATION_FAILED("lock_xchg.data")
TEST_CONFORMANCE_VERIFICATION_FAILED("lock_xchg32.data")
TEST_CONFORMANCE_VERIFICATION_FAILED("lock_xor.data")
TEST_CONFORMANCE_VERIFICATION_FAILED("lock_xor32.data")
TEST_CONFORMANCE("lsh-reg.data")
TEST_CONFORMANCE_VERIFICATION_FAILED("mem-len.data")
TEST_CONFORMANCE("mod-by-zero-reg.data")
TEST_CONFORMANCE("mod.data")
TEST_CONFORMANCE("mod32.data")
TEST_CONFORMANCE("mod64-by-zero-reg.data")
TEST_CONFORMANCE_TOP("mod64.data")
TEST_CONFORMANCE("mov.data")
TEST_CONFORMANCE("mov64-sign-extend.data")
TEST_CONFORMANCE("mul32-imm.data")
TEST_CONFORMANCE("mul32-reg-overflow.data")
TEST_CONFORMANCE("mul32-reg.data")
TEST_CONFORMANCE("mul64-imm.data")
TEST_CONFORMANCE("mul64-reg.data")
TEST_CONFORMANCE("neg.data")
TEST_CONFORMANCE("neg64.data")
TEST_CONFORMANCE_RANGE("prime.data", "[0, 1]")
TEST_CONFORMANCE("rsh-reg.data")
TEST_CONFORMANCE("rsh32.data")
TEST_CONFORMANCE_VERIFICATION_FAILED("stack.data")
TEST_CONFORMANCE("stb.data")
TEST_CONFORMANCE("stdw.data")
TEST_CONFORMANCE("sth.data")
TEST_CONFORMANCE("stw.data")
TEST_CONFORMANCE_TOP("stxb-all.data")
TEST_CONFORMANCE_TOP("stxb-all2.data")
TEST_CONFORMANCE_TOP("stxb-chain.data")
TEST_CONFORMANCE("stxb.data")
TEST_CONFORMANCE("stxdw.data")
TEST_CONFORMANCE("stxh.data")
TEST_CONFORMANCE("stxw.data")
TEST_CONFORMANCE_VERIFICATION_FAILED("subnet.data")
