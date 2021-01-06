// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

struct ebpf_verifier_options_t {
    bool print_invariants;
    bool print_failures;
};

extern const ebpf_verifier_options_t ebpf_verifier_default_options;
