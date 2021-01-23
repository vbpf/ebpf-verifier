// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

// This file provides a Platform Abstraction Layer where any environment
// that supports eBPF can have an ebpf_platform_t struct that the verifier
// can use to call platform-specific functions.

#include "spec_type_descriptors.hpp"
#include "helpers.hpp"

typedef EbpfProgramType (*ebpf_get_program_type_fn)(const std::string& section, const std::string& path);

typedef EbpfHelperPrototype (*ebpf_get_helper_prototype_fn)(unsigned int n);

typedef bool (*ebpf_is_helper_usable_fn)(unsigned int n);

struct ebpf_platform_t {
    ebpf_get_program_type_fn get_program_type;
    ebpf_get_helper_prototype_fn get_helper_prototype;
    ebpf_is_helper_usable_fn is_helper_usable;
};

extern const ebpf_platform_t g_ebpf_platform_linux;
