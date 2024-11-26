// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

/*
 * Builder for cfg_t.
 */
#include <cassert>

#include "asm_syntax.hpp"
#include "crab/cfg.hpp"
#include "crab_utils/debug.hpp"

namespace crab {

struct cfg_builder_t final {
    cfg_t cfg;

    void insert_after(const label_t& prev_label, const label_t& new_label) {
        if (prev_label == new_label) {
            CRAB_ERROR("Cannot insert after the same label ", to_string(new_label));
        }
        std::set<label_t> prev_children;
        std::swap(prev_children, cfg.get_node(prev_label).children);

        for (const label_t& next_label : prev_children) {
            cfg.get_node(next_label).parents.erase(prev_label);
        }

        insert(new_label);
        for (const label_t& next_label : prev_children) {
            add_child(prev_label, new_label);
            add_child(new_label, next_label);
        }
    }

    void insert(const label_t& _label) {
        const auto it = cfg.m_map.find(_label);
        if (it == cfg.m_map.end()) {
            cfg.m_map.emplace(_label, cfg_t::adjacent_t{});
        }
    }

    label_t make_jump(const label_t& from, const label_t& to) {
        const label_t jump_label = label_t::make_jump(from, to);
        if (cfg.contains(jump_label)) {
            CRAB_ERROR("Jump label ", to_string(jump_label), " already exists");
        }
        insert(jump_label);
        add_child(from, jump_label);
        add_child(jump_label, to);
        return jump_label;
    }

    void add_child(const label_t& a, const label_t& b) {
        assert(b != label_t::entry);
        assert(a != label_t::exit);
        cfg.m_map.at(a).children.insert(b);
        cfg.m_map.at(b).parents.insert(a);
    }

    void remove_child(const label_t& a, const label_t& b) {
        cfg.get_node(a).children.erase(b);
        cfg.get_node(b).parents.erase(a);
    }
};

class InvalidControlFlow final : public std::runtime_error {
  public:
    explicit InvalidControlFlow(const std::string& what) : std::runtime_error(what) {}
};

} // end namespace crab
