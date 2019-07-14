#include "crab/linear_constraints.hpp"

namespace ikos {
    template class linear_expression<number_t, crab::varname_t>;
    template class linear_constraint<number_t, crab::varname_t>;
    template class linear_constraint_system<number_t, crab::varname_t>;
}