// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#include "stats.hpp"

#include <optional>
#ifdef _WIN32
#include <windows.h>
#undef max
#else
#include <sys/resource.h>
#include <sys/time.h>
#endif

namespace crab {

thread_local crab::lazy_allocator<std::map<std::string, unsigned>> CrabStats::counters;
thread_local crab::lazy_allocator<std::map<std::string, Stopwatch>> CrabStats::sw;

void CrabStats::clear_thread_local_state()
{
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
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    long r = ru.ru_utime.tv_sec * 1000000L + ru.ru_utime.tv_usec;
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

void Stopwatch::resume() {
    if (finished >= started) {
        timeElapsed += finished - started;
        started = systemTime();
        finished = -1;
    }
}

long Stopwatch::getTimeElapsed() const {
    if (finished < started)
        return timeElapsed + systemTime() - started;
    else
        return timeElapsed + finished - started;
}

double Stopwatch::toSeconds() {
    double time = ((double)getTimeElapsed() / 1000000);
    return time;
}

void Stopwatch::Print(std::ostream& out) const {
    long time = getTimeElapsed();
    long h = time / 3600000000L;
    long m = time / 60000000L - h * 60;
    float s = ((float)time / 1000000L) - m * 60 - h * 3600;

    if (h > 0)
        out << h << "h";
    if (m > 0)
        out << m << "m";
    out << s << "s";
}

void CrabStats::reset() {
    counters.clear();
    sw.clear();
}

void CrabStats::count(const std::string& name) { ++(*counters)[name]; }
void CrabStats::count_max(const std::string& name, unsigned v) { (*counters)[name] = std::max((*counters)[name], v); }

unsigned CrabStats::uset(const std::string& n, unsigned v) { return (*counters)[n] = v; }
unsigned CrabStats::get(const std::string& n) { return (*counters)[n]; }

void CrabStats::start(const std::string& name) { (*sw)[name].start(); }
void CrabStats::stop(const std::string& name) { (*sw)[name].stop(); }
void CrabStats::resume(const std::string& name) { (*sw)[name].resume(); }

/** Outputs all statistics to std output */
void CrabStats::Print(std::ostream& OS) {
    OS << "\n\n************** STATS ***************** \n";
    for (auto& kv : (*counters))
        OS << kv.first << ": " << kv.second << "\n";
    for (auto& kv : (*sw))
        OS << kv.first << ": " << kv.second << "\n";
    OS << "************** STATS END ***************** \n";
}

void CrabStats::PrintBrunch(std::ostream& OS) {
    OS << "\n\n************** BRUNCH STATS ***************** \n";
    for (auto& kv : (*counters))
        OS << "BRUNCH_STAT " << kv.first << " " << kv.second << "\n";
    for (auto& kv : (*sw))
        OS << "BRUNCH_STAT " << kv.first << " " << (kv.second).toSeconds() << "sec \n";
    OS << "************** BRUNCH STATS END ***************** \n";
}

ScopedCrabStats::ScopedCrabStats(const std::string& name, bool reset) : m_name(name) {
    if (reset) {
        m_name += ".last";
        CrabStats::start(m_name);
    } else {
        CrabStats::resume(m_name);
    }
}

ScopedCrabStats::~ScopedCrabStats() { CrabStats::stop(m_name); }

} // namespace crab
