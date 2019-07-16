#pragma once

#include <type_traits>

#include "crab/adapt_sgraph.hpp"
#include "crab/bignums.hpp"
#include "crab/safeint.hpp"
#include "crab/sparse_graph.hpp"

namespace crab {
namespace domains {

/** DBM weights (Wt) can be represented using one of the following
 * types:
 *
 * 1) basic integer type: e.g., long
 * 2) safei64
 * 3) z_number
 *
 * 1) is the fastest but things can go wrong if some DBM
 * operation overflows. 2) is slower than 1) but it checks for
 * overflow before any DBM operation. 3) is the slowest and it
 * represents weights using unbounded mathematical integers so
 * overflow is not a concern but it might not be what you need
 * when reasoning about programs with wraparound semantics.
 **/

struct SafeInt64DefaultParams {
    using Wt = safe_i64;
    using graph_t = AdaptGraph<Wt>;
};

/**
 * Helper to translate from Number to DBM Wt (graph weights).  Number
 * is the template parameter of the DBM-based abstract domain to
 * represent a number. Number might not fit into Wt type.
 **/
inline safe_i64 convert_NtoW(const z_number& n, bool& overflow) {
    overflow = false;
    if (!n.fits_slong()) {
        overflow = true;
        return 0;
    }
    return safe_i64(n);
}

} // namespace domains
} // namespace crab
