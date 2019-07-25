#include "crab/crab_syntax.hpp"

namespace crab {

static crab_os& operator<<(crab_os& o, const binary_op_t& s) {
    o << s.lhs << " = " << s.left << s.op << s.right;
    if (s.finite_width)
        o << " % 2^64";
    return o;
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

static crab_os& operator<<(crab_os& o, const data_kind_t& s) {
    switch (s) {
        case data_kind_t::offsets: return o << "S_off";
        case data_kind_t::regions: return o << "S_t";
        case data_kind_t::values: return o << "S_r";
    }
    assert(false);
}

static crab_os& operator<<(crab_os& o, const array_store_t& s) {
    return o << "array_store(" << s.array << "," << s.index << ":" << s.elem_size << "," << s.value << ")";
}

static crab_os& operator<<(crab_os& o, const array_store_range_t& s) {
    return o << "array_store_range(" << s.array << "," << s.index << "," << s.value << ",sz=" << s.width << ")";
}

static crab_os& operator<<(crab_os& o, const array_load_t& s) {
    return o << s.lhs << " = "
             << "array_load(" << s.array << "," << s.index << ",sz=" << s.elem_size << ")";
}

static crab_os& operator<<(crab_os& o, const array_havoc_t& s) {
    return o << "havoc(" << s.array << "," << s.index << ",sz=" << s.elem_size << ")";
}

crab_os& operator<<(crab_os& os, const new_statement_t& a) {
    std::visit([&](const auto& arg) { os << arg; }, a);
    return os;
}

} // namespace crab