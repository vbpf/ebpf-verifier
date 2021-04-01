// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "asm_syntax.hpp"
#include "wto.hpp"

// This is the Component() function described in figure 4 of the paper.
void wto_cycle_t::initialize(class wto_t& wto, const label_t& vertex, std::shared_ptr<wto_cycle_t>& self)
{
    // Walk the control flow graph, adding nodes to this cycle.
    for (const label_t& succ : wto.cfg().next_nodes(vertex)) {
        if (wto.dfn(succ) == 0) {
            wto.visit(succ, _components, self);
        }
    }

    // Finally, add the vertex at the start of the cycle
    // (end of the vector which stores the cycle in reverse order).
    _components.push_back(std::make_shared<wto_component_t>(vertex));
}
