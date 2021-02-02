// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

enum class EbpfHelperReturnType {
    INTEGER,
    PTR_TO_MAP_VALUE_OR_NULL,
    VOID,
};

enum class EbpfHelperArgumentType {
    DONTCARE = 0,
    ANYTHING, // All values are valid, e.g., 64-bit flags.
    CONST_SIZE,
    CONST_SIZE_OR_ZERO,
    PTR_TO_CTX,
    PTR_TO_MAP,
    PTR_TO_MAP_KEY,
    PTR_TO_MAP_VALUE,
    PTR_TO_MEM,
    PTR_TO_MEM_OR_NULL,
    PTR_TO_UNINIT_MEM,
};

// A helper function's prototype is expressed by this struct.
struct EbpfHelperPrototype {
    const char* name;

    // The return value is returned in register R0.
    EbpfHelperReturnType return_type;

    // Arguments are passed in registers R1 to R5.
    EbpfHelperArgumentType argument_type[5];
};
