// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <optional>

#include "crab/split_dbm.hpp"
#include "string_constraints.hpp"

namespace crab {

namespace domains {

class AddBottom final {
    using T = SplitDBM;
    std::optional<T> dom{};
    AddBottom() {}

  public:
    explicit AddBottom(auto&& _dom) : dom{std::forward<decltype(_dom)>(_dom)} {}
    AddBottom(const AddBottom& other) = default;
    AddBottom(AddBottom& other) = default;
    AddBottom(AddBottom&& other) = default;

    AddBottom& operator=(const AddBottom& o) = default;
    AddBottom& operator=(AddBottom&& o) = default;

    void set_to_top() {
        if (dom) {
            dom->set_to_top();
        } else {
            dom = T::top();
        }
    }

    void set_to_bottom() { dom = {}; }

    [[nodiscard]]
    bool is_bottom() const {
        return !dom;
    }

    static AddBottom top() { return AddBottom(T::top()); }

    static AddBottom bottom() { return AddBottom(); }

    [[nodiscard]]
    bool is_top() const {
        return dom && dom->is_top();
    }

    bool operator<=(const AddBottom& o) const {
        if (!dom) {
            return true;
        }
        if (!o.dom) {
            return false;
        }
        return *dom <= *o.dom;
    }

    void operator|=(const AddBottom& o) {
        if (!o.dom) {
            return;
        }
        if (!dom) {
            dom = *o.dom;
            return;
        }
        (*dom) |= *o.dom;
    }

    void operator|=(AddBottom&& o) {
        if (!o.dom) {
            return;
        }
        if (!dom) {
            dom = std::move(o.dom);
            return;
        }
        *dom |= std::move(*o.dom);
    }

    template <typename Left, typename Right>
    friend AddBottom operator|(Left&& left, Right&& right) {
        using LDOM = decltype(*std::forward<Left>(left).dom);
        using RDOM = decltype(*std::forward<Right>(right).dom);
        if (!left.dom) {
            return std::forward<Right>(right);
        }
        if (!right.dom) {
            return std::forward<Left>(left);
        }
        return AddBottom(std::forward<LDOM>(*left.dom) | std::forward<RDOM>(*right.dom));
    }

    [[nodiscard]]
    AddBottom widen(const AddBottom& o) const {
        if (!dom) {
            return o;
        }
        if (!o.dom) {
            return *this;
        }
        return AddBottom(dom->widen(*o.dom));
    }

    AddBottom operator&(const AddBottom& o) const {
        if (!dom || !o.dom) {
            return bottom();
        }
        if (auto res = (*dom).meet(*o.dom)) {
            return AddBottom(*res);
        }
        return bottom();
    }

    [[nodiscard]]
    AddBottom narrow(const AddBottom& o) const {
        if (!dom || !o.dom) {
            return bottom();
        }
        return AddBottom(dom->narrow(*o.dom));
    }

    [[nodiscard]]
    AddBottom when(const linear_constraint_t& cst) const {
        if (dom) {
            AddBottom result(*dom);
            if (!result.dom->add_constraint(cst)) {
                result.dom = {};
            }
            return result;
        }
        return bottom();
    }

    void operator-=(variable_t v) {
        if (dom) {
            (*dom) -= v;
        }
    }

    void assign(std::optional<variable_t> x, const linear_expression_t& e) {
        if (x) {
            assign(*x, e);
        }
    }

    template <typename V>
    void assign(variable_t x, const V& value) {
        if (dom) {
            // XXX: maybe needs to return false when becomes bottom
            // is this possible?
            dom->assign(x, value);
        }
    };

    template <typename Op, typename Left, typename Right>
    void apply(Op op, variable_t x, const Left& left, const Right& right, int finite_width) {
        if (dom) {
            dom->apply(op, x, left, right, finite_width);
        }
    }

    void operator+=(const linear_constraint_t& cst) {
        if (dom) {
            if (!dom->add_constraint(cst)) {
                dom = {};
            }
        }
    }

    [[nodiscard]]
    interval_t eval_interval(const linear_expression_t& e) const {
        if (dom) {
            return dom->eval_interval(e);
        }
        return interval_t::bottom();
    }

    interval_t operator[](variable_t x) const {
        if (dom) {
            return (*dom)[x];
        }
        return interval_t::bottom();
    }

    void set(variable_t x, const interval_t& intv) {
        if (intv.is_bottom()) {
            dom = {};
        } else if (dom) {
            dom->set(x, intv);
        }
    }

    // Return true if inv intersects with cst.
    [[nodiscard]]
    bool intersect(const linear_constraint_t& cst) const {
        if (dom) {
            return dom->intersect(cst);
        }
        return false;
    }

    // Return true if entails rhs.
    [[nodiscard]]
    bool entail(const linear_constraint_t& cst) const {
        if (dom) {
            return dom->entail(cst);
        }
        return true;
    }

    friend std::ostream& operator<<(std::ostream& o, const AddBottom& dom) {
        if (dom.dom) {
            return o << *dom.dom;
        }
        return o << "_|_";
    }

    [[nodiscard]]
    string_invariant to_set() const {
        if (dom) {
            return dom->to_set();
        }
        return string_invariant::bottom();
    }
}; // class AddBottom

} // namespace domains
} // namespace crab
