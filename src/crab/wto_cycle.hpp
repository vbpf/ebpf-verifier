// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

using wto_vertex_t = crab::label_t;

// Bournacle, "Efficient chaotic iteration strategies with widenings", 1993
// section 3 uses the term "nested component" to refer to what wto_cycle_t implements.
class wto_cycle_t final {
    // The cycle containing this cycle, or null if there is no parent cycle.
    std::weak_ptr<wto_cycle_t> _containing_cycle;

    // List of subcomponents (i.e., vertices or other cycles) contained in this cycle.
    wto_partition_t _components;

  public:
    wto_cycle_t(std::weak_ptr<wto_cycle_t>& containing_cycle) : _containing_cycle(containing_cycle) {}

    // Finish initializing this cycle.  This must be done right after construction, where
    // 'self' is a shared pointer pointing to this instance.
    void initialize(class wto_t& wto, const wto_vertex_t& vertex, std::shared_ptr<wto_cycle_t>& self);

    // Get a vertex of an entry point of the cycle.
    [[nodiscard]] const wto_vertex_t& head() const {
        // Any cycle must start with a vertex, not another cycle,
        // per Definition 1 in the paper.  Since the vector is in reverse
        // order, the head is the last element.
        return std::get<wto_vertex_t>(*_components.back().get());
    }

    [[nodiscard]] wto_partition_t& components() { return _components; }
    [[nodiscard]] std::weak_ptr<wto_cycle_t> containing_cycle() const { return _containing_cycle; }
};

inline std::ostream& operator<<(std::ostream& o, wto_cycle_t& e) {
    o << "( ";
    for (auto it = e.components().rbegin(); it != e.components().rend(); it++) {
        wto_component_t* component = it->get();
        std::visit([&o](auto& e) -> std::ostream& { return o << e; }, *component);
        o << " ";
    }
    o << ")";
    return o;
}

inline std::ostream& operator<<(std::ostream& o, std::shared_ptr<wto_cycle_t>& e) {
    if (e != nullptr) {
        o << *e.get();
    }
    return o;
}

inline std::ostream& operator<<(std::ostream& o, wto_partition_t& partition) {
    for (auto it = partition.rbegin(); it != partition.rend(); it++) {
        wto_component_t* component = it->get();
        std::visit([&o](auto& e) -> std::ostream& { return o << e; }, *component) << " ";
    }
    return o;
}
