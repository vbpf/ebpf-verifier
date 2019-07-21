#include "crab/crab_syntax.hpp"

namespace crab {

static crab_os& operator<<(crab_os& o, const binary_op_t& s) {
    return o << s.lhs << " = " << s.left << s.op << s.right;
}
static crab_os& operator<<(crab_os& o, const assign_t& s) { return o << s.lhs << " = " << s.rhs; }
static crab_os& operator<<(crab_os& o, const assume_t& s) { return o << "assume(" << s.constraint << ")"; }
static crab_os& operator<<(crab_os& o, const havoc_t& s) { return o << "havoc(" << s.lhs << ")"; }
static crab_os& operator<<(crab_os& o, const select_t& s) {
    return o << s.lhs << " = "
             << "ite(" << s.cond << "," << s.left << "," << s.right << ")";
}
static crab_os& operator<<(crab_os& o, const assert_t& s) {
    o << "assert(" << s.constraint << ")";
    if (s.debug.has_debug()) {
        o << " // line=" << s.debug.line << " column=" << s.debug.col;
    }
    return o;
}
static crab_os& operator<<(crab_os& o, const array_store_t& s) {
    o << "array_store(" << s.array << "," << s.lb_index;
    if (!s.lb_index.equal(s.ub_index)) {
        o << ".." << s.ub_index;
    }
    o << "," << s.value << ",sz=" << s.elem_size << ")";
    return o;
}
static crab_os& operator<<(crab_os& o, const array_load_t& s) {
    return o << s.lhs << " = "
             << "array_load(" << s.array << "," << s.index << ",sz=" << s.elem_size << ")";
}

crab_os& operator<<(crab_os& os, const new_statement_t& a) {
    std::visit([&](const auto& arg) { os << arg; }, a);
    return os;
}

} // namespace crab