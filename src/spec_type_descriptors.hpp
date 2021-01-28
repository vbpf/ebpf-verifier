// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

constexpr int EBPF_STACK_SIZE = 512;

struct EbpfMapDescriptor {
    int original_fd;
    uint32_t type; // Platform-specific type value in ELF file.
    unsigned int key_size;
    unsigned int value_size;
    unsigned int inner_map_fd;
};

// The following struct describes how to access the layout in
// memory of the data (e.g., the actual packet).
struct EbpfContextDescriptor {
    int size{};     // Size of ctx struct.
    int data = -1;  // Offset into ctx struct of pointer to data.
    int end = -1;   // Offset into ctx struct of pointer to end of data.
    int meta = -1;  // Offset into ctx struct of pointer to metadata.
};
