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

class cfg_builder_t final {
    cfg_t m_cfg;

  public:
    cfg_builder_t() = default;

    const cfg_t& cfg() const { return m_cfg; }

    void insert_after(const label_t& prev_label, const label_t& new_label) {
        if (prev_label == new_label) {
            CRAB_ERROR("Cannot insert after the same label ", to_string(new_label));
        }
        insert(new_label);
        auto& prev = m_cfg.get_node(prev_label);
        const cfg_t::label_vec_t children = prev.children;
        prev.children.clear();

        for (const label_t& next_label : children) {
            m_cfg.get_node(next_label).parents.erase(prev_label);
        }

        for (const label_t& next : children) {
            add_child(prev_label, new_label);
            add_child(new_label, next);
        }
    }

    void insert(const label_t& _label) {
        const auto it = m_cfg.m_map.find(_label);
        if (it == m_cfg.m_map.end()) {
            m_cfg.m_map.emplace(_label, cfg_t::adjacent_t{});
        }
    }

    label_t make_jump(const label_t& from, const label_t& to) {
        const label_t jump_label = label_t::make_jump(from, to);
        if (m_cfg.contains(jump_label)) {
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
        m_cfg.m_map.at(a).children.insert(b);
        m_cfg.m_map.at(b).parents.insert(a);
    }

    void remove_child(const label_t& a, const label_t& b) {
        m_cfg.get_node(a).children.erase(b);
        m_cfg.get_node(b).parents.erase(a);
    }
};

class InvalidControlFlow final : public std::runtime_error {
  public:
    explicit InvalidControlFlow(const std::string& what) : std::runtime_error(what) {}
};

} // end namespace crab
