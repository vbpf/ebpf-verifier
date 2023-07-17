// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "config.hpp"

const ebpf_verifier_options_t ebpf_verifier_default_options = {
    .check_termination = false,
    .assume_assertions = false,
    .print_invariants = false,
    .print_failures = false,
    .no_simplify = false,
    .mock_map_fds = true,
    .strict = false,
    .print_line_info = false,
    .allow_division_by_zero = true,
    .setup_constraints = true,
};
