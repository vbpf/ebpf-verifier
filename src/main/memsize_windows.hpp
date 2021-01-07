// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <windows.h>
#include <Psapi.h>

inline long resident_set_size_kb() {
    PROCESS_MEMORY_COUNTERS info;
    BOOL ok = GetProcessMemoryInfo(GetCurrentProcess(), &info, sizeof(info));
    return (long)((ok) ? (info.WorkingSetSize / 1024) : 0);
}
