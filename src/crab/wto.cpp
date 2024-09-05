// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "wto.hpp"

// This file contains an iterative implementation of the recursive algorithm in
// Bourdoncle, "Efficient chaotic iteration strategies with widenings", 1993
// http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.38.3574
// where _visit_stack is roughly equivalent to a stack trace in the recursive
// algorithm.  However, this scales much higher since it does not run out of
// stack memory.

bool wto_nesting_t::operator>(const wto_nesting_t& nesting) const {
    const size_t this_size = this->_heads.size();
    const size_t other_size = nesting._heads.size();
    if (this_size <= other_size) {
        // Can't be a superset.
        return false;
    }

    // Compare entries one at a time starting from the outermost
    // (i.e., end of the vectors).
    for (size_t index = 0; index < other_size; index++) {
        if (this->_heads[this_size - 1 - index] != nesting._heads[other_size - 1 - index]) {
            return false;
        }
    }
    return true;
}

void wto_t::push_successors(const label_t& vertex, wto_partition_t& partition,
                            const std::weak_ptr<wto_cycle_t>& containing_cycle) {
    if (_vertex_data[vertex].dfn != 0) {
        // We found an alternate path to a node already visited, so nothing to do.
        return;
    }
    _vertex_data[vertex].dfn = ++_num;
    _stack.push(vertex);

    // Schedule the next task for this vertex once we're done with anything else.
    _visit_stack.emplace(visit_task_type_t::StartVisit, vertex, partition, containing_cycle);

    for (const label_t& succ : _cfg.next_nodes_reversed(vertex)) {
        if (_vertex_data[succ].dfn == 0) {
            _visit_stack.emplace(visit_task_type_t::PushSuccessors, succ, partition, containing_cycle);
        }
    }
}

void wto_t::start_visit(const label_t& vertex, wto_partition_t& partition,
                        std::weak_ptr<wto_cycle_t> containing_cycle) {
    wto_vertex_data_t& vertex_data = _vertex_data[vertex];
    int head_dfn = vertex_data.dfn;
    bool loop = false;
    int min_dfn = INT_MAX;
    for (const label_t& succ : _cfg.next_nodes(vertex)) {
        const wto_vertex_data_t& data = _vertex_data[succ];
        if (data.head_dfn != 0 && data.dfn != INT_MAX) {
            min_dfn = data.head_dfn;
        } else {
            min_dfn = data.dfn;
        }
        if (min_dfn <= head_dfn) {
            head_dfn = min_dfn;
            loop = true;
        }
    }

    // Create a new cycle component inside the containing cycle.
    const auto cycle = std::make_shared<wto_cycle_t>(containing_cycle);

    if (head_dfn == vertex_data.dfn) {
        vertex_data.dfn = INT_MAX;
        label_t element = _stack.top();
        _stack.pop();
        if (loop) {
            while (element != vertex) {
                _vertex_data[element].dfn = 0;
                _vertex_data[element].head_dfn = 0;
                element = _stack.top();
                _stack.pop();
            }
            vertex_data.head_dfn = head_dfn;

            // Stash a reference to the cycle.
            _vertex_data[vertex].containing_cycle = cycle;

            // Schedule the next task for this vertex once we're done with anything else.
            _visit_stack.emplace(visit_task_type_t::ContinueVisit, vertex, partition, cycle);

            // Walk the control flow graph, adding nodes to this cycle.
            // This is the Component() function described in figure 4 of the paper.
            for (const label_t& succ : _cfg.next_nodes_reversed(vertex)) {
                if (_vertex_data.at(succ).dfn == 0) {
                    _visit_stack.emplace(visit_task_type_t::PushSuccessors, succ, cycle->components(), cycle);
                }
            }
            return;
        } else {
            // Create a new vertex component.
            const auto component = std::make_shared<wto_component_t>(wto_component_t(vertex));

            // Insert the vertex into the current partition.
            partition.push_back(component);

            // Remember that we put the vertex into the caller's cycle.
            _containing_cycle.emplace(vertex, containing_cycle);
        }
    }
    vertex_data.head_dfn = head_dfn;
}

void wto_t::continue_visit(const label_t& vertex, wto_partition_t& partition,
                           const std::weak_ptr<wto_cycle_t>& containing_cycle) {
    // Add the vertex at the start of the cycle
    // (end of the vector which stores the cycle in reverse order).
    auto cycle = containing_cycle.lock();

    cycle->components().push_back(std::make_shared<wto_component_t>(vertex));

    // Insert the component into the current partition.
    auto component = std::make_shared<wto_component_t>(cycle);
    partition.emplace_back(component);

    // Remember that we put the vertex into the new cycle.
    _containing_cycle.emplace(vertex, cycle);
}

wto_t::wto_t(const cfg_t& cfg) : _cfg(cfg) {
    // Create a map for holding a "depth-first number (DFN)" for each vertex.
    for (const label_t& label : cfg.labels()) {
        _vertex_data.emplace(label, 0);
    }

    // Initialize the DFN counter.
    _num = 0;

    // Push the entry vertex on the stack to process.
    const visit_args_t args(visit_task_type_t::PushSuccessors, cfg.entry_label(), _components, {});
    _visit_stack.push(args);

    // Keep processing tasks until we're done.
    while (!_visit_stack.empty()) {
        visit_args_t args2 = _visit_stack.top();
        _visit_stack.pop();
        switch (args2.type) {
        case visit_task_type_t::PushSuccessors:
            push_successors(args2.vertex, args2.partition, args2.containing_cycle);
            break;
        case visit_task_type_t::StartVisit: start_visit(args2.vertex, args2.partition, args2.containing_cycle); break;
        case visit_task_type_t::ContinueVisit:
            continue_visit(args2.vertex, args2.partition, args2.containing_cycle);
            break;
        default: break;
        }
    }
}

inline std::ostream& operator<<(std::ostream& o, wto_cycle_t& cycle) {
    o << "( ";
    for (auto& component : cycle) {

        // For some reason, an Ubuntu Release build can't find the right
        // function to call via std::visit and just outputs a pointer
        // value, so we force it to use the right one here.
        if (const wto_component_t* c = component.get(); std::holds_alternative<std::shared_ptr<wto_cycle_t>>(*c)) {
            auto ptr = std::get<std::shared_ptr<class wto_cycle_t>>(*c);
            o << *ptr;
        } else {
            std::visit([&o](auto& e) -> std::ostream& { return o << e; }, *component);
        }
        o << " ";
    }
    o << ")";
    return o;
}

std::ostream& operator<<(std::ostream& o, const std::shared_ptr<wto_cycle_t>& e) {
    if (e != nullptr) {
        o << *e;
    }
    return o;
}

std::ostream& operator<<(std::ostream& o, wto_partition_t& partition) {
    for (auto& p : std::ranges::reverse_view(partition)) {
        wto_component_t* component = p.get();
        std::visit([&o](auto& e) -> std::ostream& { return o << e; }, *component) << " ";
    }
    return o;
}

// Get the vertex at the head of the component containing a given
// label, as discussed in section 4.2 of the paper.  If the label
// is itself a head of a component, we want the head of whatever
// contains that entire component.  Returns nullopt if the label is
// not nested, i.e., the head is logically the entry point of the CFG.
std::optional<label_t> wto_t::head(const label_t& label) {
    const auto it = _containing_cycle.find(label);
    if (it == _containing_cycle.end()) {
        // Label is not in any cycle.
        return {};
    }
    const std::shared_ptr<wto_cycle_t> cycle = it->second.lock();
    if (cycle == nullptr) {
        return {};
    }
    if (const label_t& first = cycle->head(); first != label) {
        // Return the head of the cycle the label is inside.
        return first;
    }

    // This label is already the head of a cycle, so get the cycle's parent.
    const std::shared_ptr<wto_cycle_t> parent = cycle->containing_cycle().lock();
    if (parent == nullptr) {
        return {};
    }
    return parent->head();
}

std::vector<label_t> wto_t::collect_heads(const label_t& label) {
    std::vector<label_t> heads;
    for (auto h = head(label); h; h = head(*h)) {
        heads.push_back(*h);
    }
    return heads;
}

// Compute the set of heads of the nested components containing a given label.
// See section 3.1 of the paper for discussion, which uses the notation w(c).
const wto_nesting_t& wto_t::nesting(const label_t& label) {
    if (!_nesting.contains(label)) {
        // Not found in the cache yet, so construct the list of heads of the
        // nested components containing the label, stored in reverse order.=
        _nesting.emplace(label, collect_heads(label));
    }
    return _nesting.at(label);
}
