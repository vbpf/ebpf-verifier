// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "crab/cfg.hpp"

struct ebpf_verifier_options_t {
    prepare_cfg_options cfg_opts;
    bool assume_assertions = false;
    bool print_invariants = false;
    bool print_failures = false;

    // False to use actual map fd's, true to use mock fd's.
    bool mock_map_fds = true;

    // True to do additional checks for some things that would fail at runtime.
    bool strict = false;

    bool print_line_info = false;
    bool allow_division_by_zero = true;
    bool setup_constraints = true;
    bool big_endian = false;

    bool dump_btf_types_json = false;
};

struct ebpf_verifier_stats_t {
    int total_unreachable;
    int total_warnings;
    int max_loop_count;
};

extern thread_local ebpf_verifier_options_t thread_local_options;
