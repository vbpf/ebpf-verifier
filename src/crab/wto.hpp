// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

// wto.hpp and wto.cpp implement Weak Topological Ordering as defined in
// Bourdoncle, "Efficient chaotic iteration strategies with widenings", 1993
// http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.38.3574
//
// Using the example from section 3.1 in the paper, the graph:
//
//         4 --> 5 <-> 6
//         ^ \________ |
//         |          vv
//         3 <-------- 7
//         ^           |
//         |           v
//   1 --> 2 --------> 8
//
// results in the WTO: 1 2 (3 4 (5 6) 7) 8
// where a single vertex is represented via label_t, and a
// cycle such as (5 6) is represented via a wto_cycle_t.
// Each arrow points to a wto_component_t, which can be either a
// single vertex such as 8, or a cycle such as (5 6).

#include <memory>
#include <ostream>
#include <ranges>
#include <stack>
#include <utility>
#include <vector>

#include "crab/cfg.hpp"

// Bourdoncle, "Efficient chaotic iteration strategies with widenings", 1993
// uses the notation w(c) to refer to the set of heads of the nested components
// containing a vertex c.  This class holds such a set of heads.  The table
// mapping c to w(c) is stored outside the class, in wto_t._nesting.
class wto_nesting_t final {
    // To optimize insertion performance, the list of heads is stored in reverse
    // order, i.e., from innermost to outermost cycle.
    std::vector<label_t> _heads;

  public:
    explicit wto_nesting_t(std::vector<label_t>&& heads) : _heads(std::move(heads)) {}

    // Test whether this nesting is a longer subset of another nesting.
    bool operator>(const wto_nesting_t& nesting) const;

    // Output the nesting in order from outermost to innermost.
    friend std::ostream& operator<<(std::ostream& o, const wto_nesting_t& nesting) {
        for (const auto& _head : std::ranges::reverse_view(nesting._heads)) {
            o << _head << " ";
        }
        return o;
    }
};

// Define types used by both this header file and wto_cycle.hpp
using wto_component_t = std::variant<std::shared_ptr<class wto_cycle_t>, label_t>;
using wto_partition_t = std::vector<std::shared_ptr<wto_component_t>>;

enum class visit_task_type_t {
    PushSuccessors = 0,
    StartVisit = 1, // Start of the Visit() function defined in Figure 4 of the paper.
    ContinueVisit = 2,
};

struct visit_args_t {
    visit_task_type_t type;
    label_t vertex;
    wto_partition_t& partition;
    std::weak_ptr<wto_cycle_t> containing_cycle;

    visit_args_t(const visit_task_type_t t, label_t v, wto_partition_t& p, std::weak_ptr<wto_cycle_t> cc)
        : type(t), vertex(std::move(v)), partition(p), containing_cycle(std::move(cc)) {};
};

struct wto_vertex_data_t {
    // Bourdoncle's thesis (reference [4]) is all in French but expands
    // DFN as "depth first number".
    int dfn{};
    int head_dfn{}; // Head value returned from Visit() in the paper.
    std::shared_ptr<wto_cycle_t> containing_cycle;
};

// Bourdoncle, "Efficient chaotic iteration strategies with widenings", 1993
// section 3 uses the term "nested component" to refer to what wto_cycle_t implements.
class wto_cycle_t final {
    // The cycle containing this cycle, or null if there is no parent cycle.
    std::weak_ptr<wto_cycle_t> _containing_cycle;

    // List of subcomponents (i.e., vertices or other cycles) contained in this cycle.
    wto_partition_t _components;

  public:
    explicit wto_cycle_t(const std::weak_ptr<wto_cycle_t>& containing_cycle) : _containing_cycle(containing_cycle) {}

    // Get a vertex of an entry point of the cycle.
    [[nodiscard]]
    const label_t& head() const {
        // Any cycle must start with a vertex, not another cycle,
        // per Definition 1 in the paper.  Since the vector is in reverse
        // order, the head is the last element.
        return std::get<label_t>(*_components.back().get());
    }

    [[nodiscard]]
    wto_partition_t::reverse_iterator begin() {
        return _components.rbegin();
    }

    [[nodiscard]]
    wto_partition_t::reverse_iterator end() {
        return _components.rend();
    }

    [[nodiscard]]
    std::weak_ptr<wto_cycle_t> containing_cycle() const {
        return _containing_cycle;
    }

    [[nodiscard]]
    wto_partition_t& components() {
        return _components;
    }
};

std::ostream& operator<<(std::ostream& o, wto_cycle_t& cycle);

std::ostream& operator<<(std::ostream& o, const std::shared_ptr<wto_cycle_t>& e);

std::ostream& operator<<(std::ostream& o, wto_partition_t& partition);

class wto_t final {
    // Original control-flow graph.
    const cfg_t& _cfg;

    // The following members are named to match the names in the paper.
    std::map<label_t, wto_vertex_data_t> _vertex_data;
    int _num; // Highest DFN used so far.
    std::stack<label_t> _stack;

    std::stack<visit_args_t> _visit_stack;

    // Top level components, in reverse order.
    wto_partition_t _components;

    // Table mapping label to the cycle containing the label.
    std::map<label_t, std::weak_ptr<wto_cycle_t>> _containing_cycle;

    // Table mapping label to the list of heads of cycles containing the label.
    // This is an on-demand cache, since for most vertices the nesting is never
    // looked at so we only create a wto_nesting_t for cases we actually need it.
    std::map<label_t, wto_nesting_t> _nesting;

    void push_successors(const label_t& vertex, wto_partition_t& partition,
                         const std::weak_ptr<wto_cycle_t>& containing_cycle);
    void start_visit(const label_t& vertex, wto_partition_t& partition, std::weak_ptr<wto_cycle_t> containing_cycle);
    void continue_visit(const label_t& vertex, wto_partition_t& partition,
                        const std::weak_ptr<wto_cycle_t>& containing_cycle);

    std::vector<label_t> collect_heads(const label_t& label);
    std::optional<label_t> head(const label_t& label);

  public:
    // Construct a Weak Topological Ordering from a control-flow graph using
    // the algorithm of figure 4 in the paper, where this constructor matches
    // what is shown there as the Partition function.
    explicit wto_t(const cfg_t& cfg);

    [[nodiscard]]
    wto_partition_t::reverse_iterator begin() {
        return _components.rbegin();
    }

    [[nodiscard]]
    wto_partition_t::reverse_iterator end() {
        return _components.rend();
    }

    friend std::ostream& operator<<(std::ostream& o, wto_t& wto) { return o << wto._components << std::endl; }
    const wto_nesting_t& nesting(const label_t& label);
};
