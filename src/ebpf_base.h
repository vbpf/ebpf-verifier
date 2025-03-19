// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

// This file contains type definitions that can be used in C or C++
// that would typically be shared between the verifier and other
// eBPF components.

typedef enum _ebpf_return_type {
    EBPF_RETURN_TYPE_INTEGER = 0,
    EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
    EBPF_RETURN_TYPE_INTEGER_OR_NO_RETURN_IF_SUCCEED,
    EBPF_RETURN_TYPE_UNSUPPORTED,
} ebpf_return_type_t;

typedef enum _ebpf_argument_type {
    EBPF_ARGUMENT_TYPE_DONTCARE = 0,
    EBPF_ARGUMENT_TYPE_ANYTHING, // All values are valid, e.g., 64-bit flags.
    EBPF_ARGUMENT_TYPE_CONST_SIZE,
    EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
    EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
    EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
    EBPF_ARGUMENT_TYPE_PTR_TO_MAP_OF_PROGRAMS,
    EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY,
    EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE,
    EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, // Memory must have been initialized.
    EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL,
    EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
    EBPF_ARGUMENT_TYPE_UNSUPPORTED,
} ebpf_argument_type_t;

// The following struct describes how to access the layout in
// memory of the data (e.g., the actual packet).
typedef struct _ebpf_context_descriptor {
    int size; // Size of ctx struct.
    int data; // Offset into ctx struct of pointer to data.
    int end;  // Offset into ctx struct of pointer to end of data.
    int meta; // Offset into ctx struct of pointer to metadata.
} ebpf_context_descriptor_t;

// Maximum number of nested function calls allowed in eBPF programs.
// This limit helps prevent stack overflow and ensures predictable behavior.
#define MAX_CALL_STACK_FRAMES 8

// Stack space allocated for each subprogram (in bytes).
// This ensures each function call has its own dedicated stack space.
#define EBPF_SUBPROGRAM_STACK_SIZE 512

// Total stack space usable with nested subprogram calls.
#define EBPF_TOTAL_STACK_SIZE (MAX_CALL_STACK_FRAMES * EBPF_SUBPROGRAM_STACK_SIZE)
