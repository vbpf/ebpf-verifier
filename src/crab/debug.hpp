#pragma once

/* Logging and debug messages */

#include "crab/os.hpp"

#include <iosfwd>
#include <set>
#include <stdarg.h>
#include <string>

namespace crab {

#ifndef NCRABLOG
#define CRAB_LOG(TAG, CODE)                                            \
    do {                                                               \
        if (::crab::CrabLogFlag && ::crab::CrabLog.count(TAG) > 0) {   \
            CODE;                                                      \
        }                                                              \
    } while (0)
extern bool CrabLogFlag;
extern std::set<std::string> CrabLog;
void CrabEnableLog(std::string x);
#else
#define CRAB_LOG(TAG, CODE)                                                                                            \
    do {                                                                                                               \
    } while (0)
void CrabEnableLog(std::string x);
#endif

extern unsigned CrabVerbosity;
void CrabEnableVerbosity(unsigned v);
#define CRAB_VERBOSE_IF(LEVEL, CODE)                                                                                   \
    do {                                                                                                               \
        if (::crab::CrabVerbosity >= LEVEL) {                                                                          \
            CODE;                                                                                                      \
        }                                                                                                              \
    } while (0)

crab_os &get_msg_stream(bool timestamp = true);

template <typename... ArgTypes>
inline void ___print___(ArgTypes... args) {
    // trick to expand variadic argument pack without recursion
    using expand_variadic_pack = int[];
    // first zero is to prevent empty braced-init-list
    // void() is to prevent overloaded operator, messing things up
    // trick is to use the side effect of list-initializer to call a function
    // on every argument.
    // (void) is to suppress "statement has no effect" warnings
    (void)expand_variadic_pack{0, ((crab::errs() << args), void(), 0)...};
}

#define CRAB_ERROR(...)                                                                                                \
    do {                                                                                                               \
        crab::errs() << "CRAB ERROR: ";                                                                                \
        crab::___print___(__VA_ARGS__);                                                                                \
        crab::errs() << "\n";                                                                                          \
        std::exit(EXIT_FAILURE);                                                                                       \
    } while (0)

extern bool CrabWarningFlag;
void CrabEnableWarningMsg(bool b);

#define CRAB_WARN(...)                                                                                                 \
    do {                                                                                                               \
        if (::crab::CrabWarningFlag) {                                                                                 \
            crab::errs() << "CRAB WARNING: ";                                                                          \
            crab::___print___(__VA_ARGS__);                                                                            \
            crab::errs() << "\n";                                                                                      \
        }                                                                                                              \
    } while (0)

extern bool CrabSanityCheckFlag;
void CrabEnableSanityChecks(bool b);

} // end namespace crab
