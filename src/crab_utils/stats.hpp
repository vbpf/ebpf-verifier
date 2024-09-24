// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <map>
#include <string>

#include "crab/variable.hpp"
#include "crab_utils/lazy_allocator.hpp"

namespace crab {

class Stopwatch {
    long started;
    long finished;
    long timeElapsed;

    long systemTime() const;

  public:
    Stopwatch();
    void start();
    void stop();
    long getTimeElapsed() const;
    void Print(std::ostream& out) const;
};

inline std::ostream& operator<<(std::ostream& OS, const Stopwatch& sw) {
    sw.Print(OS);
    return OS;
}

class CrabStats {
    static thread_local crab::lazy_allocator<std::map<std::string, unsigned>> counters;
    static thread_local crab::lazy_allocator<std::map<std::string, Stopwatch>> sw;

  public:
    static void clear_thread_local_state();

    static void reset();

    /* counters */
    static unsigned get(const std::string& n);
    static void count(const std::string& name);

    /* stop watch */
    static void start(const std::string& name);
    static void stop(const std::string& name);

    /** Outputs all statistics to std output */
    static void Print(std::ostream& OS);
};

} // namespace crab
