#include "crab/crab_syntax.hpp"

namespace crab {

static std::ostream& operator<<(std::ostream& o, const binary_op_t& s) {
    o << s.lhs << " = " << s.left << s.op << s.right;
    if (s.finite_width)
        o << " % 2^64";
    return o;
}
static std::ostream& operator<<(std::ostream& o, const assign_t& s) { return o << s.lhs << " = " << s.rhs; }
static std::ostream& operator<<(std::ostream& o, const assume_t& s) { return o << "assume(" << s.constraint << ")"; }
static std::ostream& operator<<(std::ostream& o, const havoc_t& s) { return o << "havoc(" << s.lhs << ")"; }
static std::ostream& operator<<(std::ostream& o, const select_t& s) {
    return o << s.lhs << " = "
             << "ite(" << s.cond << "," << s.left << "," << s.right << ")";
}
static std::ostream& operator<<(std::ostream& o, const assert_t& s) {
    o << "assert(" << s.constraint << ")";
    if (s.debug.has_debug()) {
        o << " // line=" << s.debug.line << " column=" << s.debug.col;
    }
    return o;
}

static std::ostream& operator<<(std::ostream& o, const array_store_t& s) {
    return o << "array_store(" << s.array << "," << s.index << ":" << s.elem_size << "," << s.value << ")";
}

static std::ostream& operator<<(std::ostream& o, const array_store_range_t& s) {
    return o << "array_store_range(" << s.array << "," << s.index << "," << s.value << ",sz=" << s.width << ")";
}

static std::ostream& operator<<(std::ostream& o, const array_load_t& s) {
    return o << s.lhs << " = "
             << "array_load(" << s.array << "," << s.index << ",sz=" << s.elem_size << ")";
}

static std::ostream& operator<<(std::ostream& o, const array_havoc_t& s) {
    return o << "havoc(" << s.array << "," << s.index << ",sz=" << s.elem_size << ")";
}

std::ostream& operator<<(std::ostream& os, const new_statement_t& a) {
    std::visit([&](const auto& arg) { os << arg; }, a);
    return os;
}

} // namespace crab