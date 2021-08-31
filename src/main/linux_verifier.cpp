// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#if __linux__

#include <unistd.h>
#include <linux/bpf.h>
#include <ctime>
#include <tuple>

#include "config.hpp"
#include "linux_verifier.hpp"
#include "spec_type_descriptors.hpp"
#include "utils.hpp"

static int do_bpf(bpf_cmd cmd, union bpf_attr& attr) { return syscall(321, cmd, &attr, sizeof(attr)); }

/** Run the built-in Linux verifier on a raw eBPF program.
 *
 *  \return A pair (passed, elapsec_secs)
 */

std::tuple<bool, double> bpf_verify_program(const EbpfProgramType& type, const std::vector<ebpf_inst>& raw_prog, ebpf_verifier_options_t* options) {
    std::vector<char> buf(options->print_failures ? 1000000 : 10);
    buf[0] = 0;
    memset(buf.data(), '\0', buf.size());

    union bpf_attr attr{};
    memset(&attr, '\0', sizeof(attr));
    attr.prog_type = (__u32)type.platform_specific_data;
    attr.insn_cnt = (__u32)raw_prog.size();
    attr.insns = (__u64)raw_prog.data();
    attr.license = (__u64) "GPL";
    if (options->print_failures) {
        attr.log_buf = (__u64)buf.data();
        attr.log_size = buf.size();
        attr.log_level = 3;
    }
    attr.kern_version = 0x041800;
    attr.prog_flags = 0;

    const auto [res, elapsed_secs] = timed_execution([&] {
        return do_bpf(BPF_PROG_LOAD, attr);
    });
    if (res < 0) {
        if (options->print_failures) {
            std::cerr << "Failed to verify program: " << strerror(errno) << " (" << errno << ")\n";
            std::cerr << "LOG: " << (char*)attr.log_buf;
        }
        return {false, elapsed_secs};
    }
    return {true, elapsed_secs};
}
#endif
