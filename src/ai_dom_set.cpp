#include <algorithm>
#include <iostream>
#include <set>
#include <vector>

#include <bitset>

#include "ai_dom_set.hpp"
#include "asm_syntax.hpp"

using Set = std::vector<uint64_t>;

template <typename T>
static std::vector<T> set_union(const std::vector<T> &a, const std::vector<T> &b) {
    std::vector<T> res;
    std::set_union(a.begin(), a.end(), b.begin(), b.end(), std::back_inserter(res));
    return res;
}

template <typename T>
static std::vector<T> set_intersection(const std::vector<T> &a, const std::vector<T> &b) {
    std::vector<T> res;
    std::set_intersection(a.begin(), a.end(), b.begin(), b.end(), std::back_inserter(res));
    return res;
}

void NumDomSet::operator|=(const NumDomSet &o) {
    if (top || o.top) {
        havoc();
        return;
    }
    elems = set_union(elems, o.elems);
}

void NumDomSet::operator&=(const NumDomSet &o) {
    if (o.top) {
        return;
    }
    if (top) {
        (*this) = o;
        return;
    }
    elems = set_intersection(elems, o.elems);
}

void NumDomSet::exec(const Bin::Op op, const NumDomSet &o) {
    using Op = Bin::Op;
    if (is_bot() || o.is_bot()) {
        to_bot();
        return;
    }
    if (top || o.top) {
        havoc();
        return;
    }
    std::set<uint64_t> res;
    for (auto k : elems) {
        for (auto n : o.elems) {
            switch (op) {
            case Op::MOV: assert(false); break;
            case Op::ADD: res.insert(k + n); break;
            case Op::SUB: res.insert(k - n); break;
            case Op::MUL: res.insert(k * n); break;
            case Op::DIV: res.insert(k / n); break;
            case Op::MOD: res.insert(k % n); break;
            case Op::OR: res.insert(k | n); break;
            case Op::AND: res.insert(k & n); break;
            case Op::LSH: res.insert(k << n); break;
            case Op::RSH: res.insert((int64_t)k >> n); break;
            case Op::ARSH: res.insert(k >> n); break;
            case Op::XOR: res.insert(k ^ n); break;
            }
        }
    }
    elems.clear();
    for (uint64_t e : res)
        elems.push_back(e);
}

void OffsetDomSet::operator|=(const OffsetDomSet &o) {
    if (top || o.top) {
        havoc();
        return;
    }
    elems = set_union(elems, o.elems);
}

void OffsetDomSet::operator&=(const OffsetDomSet &o) {
    if (o.top) {
        return;
    }
    if (top) {
        (*this) = o;
        return;
    }
    elems = set_intersection(elems, o.elems);
}

void OffsetDomSet::exec(bool add, const NumDomSet &o) {
    if (is_bot() || o.is_bot()) {
        to_bot();
        return;
    }
    if (top || o.top) {
        havoc();
        return;
    }
    std::set<int64_t> res;
    for (auto k : elems) {
        for (auto n : o.elems) {
            int64_t x = add ? k + (int)n : k - (int)n;
            if (x > (1 << 30)) {
                havoc();
                return;
            }
            res.insert(x);
        }
    }

    elems.clear();
    for (int64_t e : res)
        elems.push_back(e);
}

NumDomSet OffsetDomSet::operator-(const OffsetDomSet &o) const {
    if (is_bot() || o.is_bot()) {
        return {};
    }
    if (top || o.top) {
        return NumDomSet::make_top();
    }
    std::set<int64_t> res;
    for (auto k : elems) {
        for (auto n : o.elems) {
            res.insert(k - n);
            if (k - n > (1 << 30)) {
                return NumDomSet::make_top();
            }
        }
    }

    NumDomSet out;
    for (int64_t e : res)
        out.elems.push_back(e);
    return out;
}

void NumDomSet::assume(Condition::Op op, const NumDomSet &right) {
    if (right.is_top())
        return;
    using Op = Condition::Op;
    switch (op) {
    case Op::EQ: (*this) &= right; return;
    case Op::NE: {
        std::vector<uint64_t> old;
        std::swap(old, elems);
        std::set_difference(old.begin(), old.end(), right.elems.begin(), right.elems.end(), std::back_inserter(elems));
        return;
    }
    case Op::SET: return;
    case Op::NSET: return;
    default: break;
    }
    std::vector<uint64_t> old;
    std::swap(old, elems);
    if (right.elems.empty())
        return;
    switch (op) {
    case Op::EQ:
    case Op::NE:
    case Op::SET:
    case Op::NSET: assert(false);

    case Op::GT: {
        auto m = *std::min_element(right.elems.begin(), right.elems.end());
        for (auto e : old)
            if (e > m)
                elems.push_back(e);
        break;
    }
    case Op::GE: {
        auto m = *std::min_element(right.elems.begin(), right.elems.end());
        for (auto e : old)
            if (e >= m)
                elems.push_back(e);
        break;
    }
    case Op::SGT: {
        auto m = *std::min_element(right.elems.begin(), right.elems.end(),
                                   [](auto a, auto b) { return (int64_t)a < (int64_t)b; });
        for (auto e : old)
            if ((int64_t)e > (int64_t)m)
                elems.push_back(e);
        break;
    }
    case Op::SGE: {
        auto m = *std::min_element(right.elems.begin(), right.elems.end(),
                                   [](auto a, auto b) { return (int64_t)a < (int64_t)b; });
        for (auto e : old)
            if ((int64_t)e >= (int64_t)m)
                elems.push_back(e);
        break;
    }
    case Op::LT: {
        auto m = *std::max_element(right.elems.begin(), right.elems.end());
        for (auto e : old)
            if (e < m)
                elems.push_back(e);
        break;
    }
    case Op::LE: {
        auto m = *std::max_element(right.elems.begin(), right.elems.end());
        for (auto e : old)
            if (e <= m)
                elems.push_back(e);
        break;
    }
    case Op::SLT: {
        auto m = *std::max_element(right.elems.begin(), right.elems.end(),
                                   [](auto a, auto b) { return (int64_t)a < (int64_t)b; });
        for (auto e : old)
            if ((int64_t)e < (int64_t)m)
                elems.push_back(e);
        break;
    }
    case Op::SLE: {
        auto m = *std::max_element(right.elems.begin(), right.elems.end(),
                                   [](auto a, auto b) { return (int64_t)a < (int64_t)b; });
        for (auto e : old)
            if ((int64_t)e <= (int64_t)m)
                elems.push_back(e);
        break;
    }
    }
}

void OffsetDomSet::assume(Condition::Op op, const OffsetDomSet &right) {
    if (right.is_top())
        return;
    using Op = Condition::Op;
    switch (op) {
    case Op::EQ: (*this) &= right; return;
    case Op::NE: {
        std::vector<int64_t> old;
        std::swap(old, elems);
        std::set_difference(old.begin(), old.end(), right.elems.begin(), right.elems.end(), std::back_inserter(elems));
        return;
    }
    case Op::SET: return;
    case Op::NSET: return;
    default: break;
    }
    std::vector<int64_t> old;
    std::swap(old, elems);
    if (right.elems.empty())
        return;
    switch (op) {
    case Op::GT: {
        auto m = *std::min_element(right.elems.begin(), right.elems.end());
        for (auto e : old)
            if (e > m)
                elems.push_back(e);
        break;
    }
    case Op::GE: {
        auto m = *std::min_element(right.elems.begin(), right.elems.end());
        for (auto e : old)
            if (e >= m)
                elems.push_back(e);
        break;
    }
    case Op::LT: {
        auto m = *std::max_element(right.elems.begin(), right.elems.end());
        for (auto e : old)
            if (e < m)
                elems.push_back(e);
        break;
    }
    case Op::LE: {
        auto m = *std::max_element(right.elems.begin(), right.elems.end());
        for (auto e : old)
            if (e <= m)
                elems.push_back(e);
        break;
    }
    case Op::EQ: assert(false); break;
    case Op::NE: assert(false); break;
    case Op::SET: assert(false); break;
    case Op::NSET: assert(false); break;

    case Op::SGT: assert(false); break;
    case Op::SGE: assert(false); break;
    case Op::SLT: assert(false); break;
    case Op::SLE: assert(false); break;
    }
}
