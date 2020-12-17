// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "config.hpp"

const ebpf_verifier_options_t ebpf_verifier_default_options = {
    .check_termination = false,
    .print_invariants = false,
    .print_failures = false
};
