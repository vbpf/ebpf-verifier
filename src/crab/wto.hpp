// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

// This file implements Weak Topological Ordering as defined in
// Bournacle, "Efficient chaotic iteration strategies with widenings", 1993
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

#include <stack>
#include <vector>
#include "crab/cfg.hpp"
#include "crab/wto_nesting.hpp"

// Define types used by both this header file and wto_cycle.hpp
using wto_component_t = std::variant<std::shared_ptr<class wto_cycle_t>, label_t>;
using wto_partition_t = std::vector<std::shared_ptr<wto_component_t>>;

#include "crab/wto_cycle.hpp"

class wto_t final {
    // Original control-flow graph.
    const crab::cfg_t& _cfg;

    // The following members are named to match the names in the paper,
    // which never explains their meaning.  Bourdoncle's thesis (reference [4])
    // is all in French but expands DFN as "depth first number".
    std::map<label_t, int> _dfn;
    int _num;
    std::stack<label_t> _stack;

    // Top level components, in reverse order.
    wto_partition_t _components;

    // Table mapping label to the cycle containing the label.
    std::map<label_t, std::weak_ptr<wto_cycle_t>> _containing_cycle;

    // Table mapping label to the list of heads of cycles containing the label.
    // This is an on-demand cache, since for most vertices the nesting is never
    // looked at so we only create a wto_nesting_t for cases we actually need it.
    std::map<label_t, wto_nesting_t> _nesting;

    public:

    // Implementation of the Visit() function defined in Figure 4 of the paper.
    int visit(const label_t& vertex, wto_partition_t& partition, std::weak_ptr<wto_cycle_t> containing_cycle) {
        _stack.push(vertex);
        _num++;
        int head = _dfn[vertex] = _num;
        bool loop = false;
        int min = INT_MAX;
        for (const label_t& succ : _cfg.next_nodes(vertex)) {
            if (_dfn[succ] == 0) {
                min = visit(succ, partition, containing_cycle);
            } else {
                min = _dfn[succ];
            }
            if (min <= head) {
                head = min;
                loop = true;
            }
        }
        if (head == _dfn[vertex]) {
            _dfn[vertex] = INT_MAX;
            label_t& element = _stack.top();
            _stack.pop();
            if (loop) {
                while (element != vertex) {
                    _dfn[element] = 0;
                    element = _stack.top();
                    _stack.pop();
                }

                // Create a new cycle component.
                auto cycle = std::make_shared<wto_cycle_t>(containing_cycle);
                auto component = std::make_shared<wto_component_t>(cycle);
                cycle->initialize(*this, vertex, cycle);

                // Insert the component into the current partition.
                partition.emplace_back(component);

                // Remember that we put the vertex into the new cycle.
                _containing_cycle.emplace(vertex, cycle);
            } else {
                // Create a new vertex component.
                auto component = std::make_shared<wto_component_t>(wto_component_t(vertex));

                // Insert the vertex into the current partition.
                partition.push_back(component);

                // Remember that we put the vertex into the caller's cycle.
                _containing_cycle.emplace(vertex, containing_cycle);
            }
        }
        return head;
    }

    [[nodiscard]] const crab::cfg_t& cfg() const { return _cfg; }
    [[nodiscard]] int dfn(const label_t& vertex) const { return _dfn.at(vertex); }

    // Construct a Weak Topological Ordering from a control-flow graph using
    // the algorithm of figure 4 in the paper, where this constructor matches
    // what is shown there as the Partition function.
    wto_t(const cfg_t& cfg) : _cfg(cfg) {
        for (const label_t& label : cfg.labels()) {
            _dfn.emplace(label, 0);
        }
        _num = 0;
        visit(cfg.entry_label(), _components, {});
    }

    [[nodiscard]] wto_partition_t::reverse_iterator begin() { return _components.rbegin(); }
    [[nodiscard]] wto_partition_t::reverse_iterator end() { return _components.rend(); }

    friend std::ostream& operator<<(std::ostream& o, wto_t& wto) {
        o << wto._components << std::endl;
        return o;
    }

    // Get the vertex at the head of the component containing a given
    // label, as discussed in section 4.2 of the paper.  If the label
    // is itself a head of a component, we want the head of whatever
    // contains that entire component.  Returns nullopt if the label is
    // not nested, i.e., the head is logically the entry point of the CFG.
    std::optional<label_t> head(const label_t& label) {
        auto it = _containing_cycle.find(label);
        if (it == _containing_cycle.end()) {
            // Label is not in any cycle.
            return {};
        }
        std::shared_ptr<wto_cycle_t> cycle = it->second.lock();
        if (cycle == nullptr) {
            return {};
        }
        const label_t& first = cycle->head();
        if (first != label) {
            // Return the head of the cycle the label is inside.
            return first;
        }

        // This label is already the head of a cycle, so get the cycle's parent.
        std::shared_ptr<wto_cycle_t> parent = cycle->containing_cycle().lock();
        if (parent == nullptr) {
            return {};
        }
        return parent->head();
    }

    // Compute the set of heads of the nested components containing a given label.
    // See section 3.1 of the paper for discussion, which uses the notation w(c).
    const wto_nesting_t& nesting(const label_t& label) {
        auto it = _nesting.find(label);
        if (it != _nesting.end()) {
            return it->second;
        }

        // Not found in the cache yet, so construct the list of heads of the
        // nested components containing the label, stored in reverse order.
        std::vector<label_t> heads;
        for (std::optional<label_t> h = head(label); h.has_value(); h = head(h.value())) {
            heads.push_back(h.value());
        }

        wto_nesting_t n = wto_nesting_t(std::move(heads));
        _nesting.emplace(label, std::move(n));
        return _nesting.at(label);
    }

};
