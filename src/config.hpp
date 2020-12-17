// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

struct ebpf_verifier_options_t {
    bool check_termination;
    bool print_invariants;
    bool print_failures;
};

extern const ebpf_verifier_options_t ebpf_verifier_default_options;
