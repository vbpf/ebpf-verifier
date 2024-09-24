// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#include "stats.hpp"

#ifdef _WIN32
#include <windows.h>
#undef max
#else
#include <sys/resource.h>
#endif

namespace crab {

thread_local lazy_allocator<std::map<std::string, unsigned>> CrabStats::counters;
thread_local lazy_allocator<std::map<std::string, Stopwatch>> CrabStats::sw;

void CrabStats::clear_thread_local_state() {
    counters.clear();
    sw.clear();
}

// Gets the amount of user CPU time used, in microseconds.
long Stopwatch::systemTime() const {
#ifdef _WIN32
    FILETIME creation_time, exit_time, kernel_time, user_time;
    if (!GetProcessTimes(GetCurrentProcess(), &creation_time, &exit_time, &kernel_time, &user_time)) {
        return 0;
    }

    // Convert from 100ns intervals to microseconds.
    uint64_t total_us = (((uint64_t)user_time.dwHighDateTime << 32) | (uint64_t)user_time.dwLowDateTime) / 10;

    return (long)total_us;
#else
    rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    const long r = ru.ru_utime.tv_sec * 1000000L + ru.ru_utime.tv_usec;
    return r;
#endif
}

Stopwatch::Stopwatch() { start(); }

void Stopwatch::start() {
    started = systemTime();
    finished = -1;
    timeElapsed = 0;
}

void Stopwatch::stop() {
    if (finished < started) {
        finished = systemTime();
    }
}

long Stopwatch::getTimeElapsed() const {
    if (finished < started) {
        return timeElapsed + systemTime() - started;
    } else {
        return timeElapsed + finished - started;
    }
}

void Stopwatch::Print(std::ostream& out) const {
    long time = getTimeElapsed();
    long h = time / 3600000000L;
    long m = time / 60000000L - h * 60;
    float s = (static_cast<float>(time) / 1000000L) - m * 60 - h * 3600;

    if (h > 0) {
        out << h << "h";
    }
    if (m > 0) {
        out << m << "m";
    }
    out << s << "s";
}

void CrabStats::reset() {
    counters.clear();
    sw.clear();
}

void CrabStats::count(const std::string& name) { ++(*counters)[name]; }

unsigned CrabStats::get(const std::string& n) { return (*counters)[n]; }

void CrabStats::start(const std::string& name) { (*sw)[name].start(); }
void CrabStats::stop(const std::string& name) { (*sw)[name].stop(); }

/** Outputs all statistics to std output */
void CrabStats::Print(std::ostream& OS) {
    OS << "\n\n************** STATS ***************** \n";
    for (auto& kv : (*counters)) {
        OS << kv.first << ": " << kv.second << "\n";
    }
    for (auto& kv : (*sw)) {
        OS << kv.first << ": " << kv.second << "\n";
    }
    OS << "************** STATS END ***************** \n";
}

} // namespace crab
