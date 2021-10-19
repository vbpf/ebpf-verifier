// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once
#include <memory>
#include <ostream>
#include "wto.hpp"

// Bourdoncle, "Efficient chaotic iteration strategies with widenings", 1993
// section 3 uses the term "nested component" to refer to what wto_cycle_t implements.
class wto_cycle_t final {
    // The cycle containing this cycle, or null if there is no parent cycle.
    std::weak_ptr<wto_cycle_t> _containing_cycle;

    // List of subcomponents (i.e., vertices or other cycles) contained in this cycle.
    wto_partition_t _components;

  public:
    wto_cycle_t(std::weak_ptr<wto_cycle_t>& containing_cycle) : _containing_cycle(containing_cycle) {}

    // Get a vertex of an entry point of the cycle.
    [[nodiscard]] const label_t& head() const {
        // Any cycle must start with a vertex, not another cycle,
        // per Definition 1 in the paper.  Since the vector is in reverse
        // order, the head is the last element.
        return std::get<label_t>(*_components.back().get());
    }

    [[nodiscard]] wto_partition_t::reverse_iterator begin() { return _components.rbegin(); }
    [[nodiscard]] wto_partition_t::reverse_iterator end() { return _components.rend(); }

    [[nodiscard]] std::weak_ptr<wto_cycle_t> containing_cycle() const { return _containing_cycle; }
    [[nodiscard]] wto_partition_t& components() { return _components; }
};

inline std::ostream& operator<<(std::ostream& o, wto_cycle_t& cycle) {
    o << "( ";
    for (auto& component : cycle) {
        wto_component_t* c = component.get();

        // For some reason, an Ubuntu Release build can't find the right
        // function to call via std::visit and just outputs a pointer
        // value, so we force it to use the right one here.
        if (std::holds_alternative<std::shared_ptr<class wto_cycle_t>>(*c)) {
            auto ptr = std::get<std::shared_ptr<class wto_cycle_t>>(*c);
            o << *ptr;
        } else
            std::visit([&o](auto& e) -> std::ostream& { return o << e; }, *component);
        o << " ";

    }
    o << ")";
    return o;
}

inline std::ostream& operator<<(std::ostream& o, std::shared_ptr<wto_cycle_t>& e) {
    if (e != nullptr) {
        o << *e;
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
