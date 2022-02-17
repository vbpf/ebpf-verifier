// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "wto.hpp"

#ifndef RECURSIVE_WTO

// This file contains an iterative implementation of the recursive algorithm in
// Bourdoncle, "Efficient chaotic iteration strategies with widenings", 1993
// http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.38.3574
// where _visit_stack is roughly equivalent to a stack trace in the recursive
// algorithm.  However, this scales much higher since it does not run out of
// stack memory.

void wto_t::push_successors(const label_t& vertex, wto_partition_t& partition,
                            std::weak_ptr<wto_cycle_t> containing_cycle) {
    if (_vertex_data[vertex].dfn != 0) {
        // We found an alternate path to a node already visited, so nothing to do.
        return;
    }
    _vertex_data[vertex].dfn = ++_num;
    _stack.push(vertex);

    // Schedule the next task for this vertex once we're done with anything else.
    visit_args_t args(visit_task_type_t::StartVisit, vertex, partition, containing_cycle);
    _visit_stack.push(args);

    for (const label_t& succ : _cfg.next_nodes_reversed(vertex)) {
        if (_vertex_data[succ].dfn == 0) {
            visit_args_t args(visit_task_type_t::PushSuccessors, succ, partition, containing_cycle);
            _visit_stack.push(args);
        }
    }
}

void wto_t::start_visit(const label_t& vertex, wto_partition_t& partition, std::weak_ptr<wto_cycle_t> containing_cycle) {
    wto_vertex_data_t& vertex_data = _vertex_data[vertex];
    int head_dfn = vertex_data.dfn;
    bool loop = false;
    int min_dfn = INT_MAX;
    for (const label_t& succ : _cfg.next_nodes(vertex)) {
        wto_vertex_data_t& data = _vertex_data[succ];
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
    auto cycle = std::make_shared<wto_cycle_t>(containing_cycle);

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
            visit_args_t args2(visit_task_type_t::ContinueVisit, vertex, partition, cycle);
            _visit_stack.push(args2);

            // Walk the control flow graph, adding nodes to this cycle.
            // This is the Component() function described in figure 4 of the paper.
            for (const label_t& succ : _cfg.next_nodes_reversed(vertex)) {
                if (dfn(succ) == 0) {
                    visit_args_t args(visit_task_type_t::PushSuccessors, succ, cycle->components(), cycle);
                    _visit_stack.push(args);
                }
            }
            return;
        } else {
            // Create a new vertex component.
            auto component = std::make_shared<wto_component_t>(wto_component_t(vertex));

            // Insert the vertex into the current partition.
            partition.push_back(component);

            // Remember that we put the vertex into the caller's cycle.
            _containing_cycle.emplace(vertex, containing_cycle);
        }
    }
    vertex_data.head_dfn = head_dfn;
}

void wto_t::continue_visit(const label_t& vertex, wto_partition_t& partition,
                        std::weak_ptr<wto_cycle_t> containing_cycle) {
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
    visit_args_t args(visit_task_type_t::PushSuccessors, cfg.entry_label(), _components, {});
    _visit_stack.push(args);

    // Keep processing tasks until we're done.
    while (!_visit_stack.empty()) {
        visit_args_t& args2 = _visit_stack.top();
        _visit_stack.pop();
        switch (args2.type) {
        case visit_task_type_t::PushSuccessors: push_successors(args2.vertex, args2.partition, args2.containing_cycle); break;
        case visit_task_type_t::StartVisit: start_visit(args2.vertex, args2.partition, args2.containing_cycle); break;
        case visit_task_type_t::ContinueVisit: continue_visit(args2.vertex, args2.partition, args2.containing_cycle); break;
        default: break;
        }
    }
}
#endif
