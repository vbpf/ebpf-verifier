// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "config.hpp"
#include "platform.hpp"

const ebpf_verifier_options_t ebpf_verifier_default_options = {
    .check_termination = false,
    .assume_assertions = false,
    .print_invariants = false,
    .print_failures = false,
    .no_simplify = false,
    .mock_map_fds = true,
    .strict = false,
    .spectre_PHT = false,
    .spectre_SSB = false,
    .spectre_SLF = false,
};
