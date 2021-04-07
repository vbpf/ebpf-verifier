// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

struct ebpf_verifier_options_t {
    bool check_termination;
    bool print_invariants;
    bool print_failures;
    bool no_simplify;

    // False to use actual map fd's, true to use mock fd's.
    bool mock_map_fds;

    // True to do additional checks for some things that would fail at runtime.
    bool strict;
};

extern const ebpf_verifier_options_t ebpf_verifier_default_options;
