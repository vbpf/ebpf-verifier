// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

/*
 * Build a CFG to interface with the abstract domains and fixpoint iterators.
 */
#include <map>
#include <memory>
#include <set>
#include <variant>
#include <vector>

#include <boost/iterator/transform_iterator.hpp>
#include <boost/lexical_cast.hpp>
#include <gsl/gsl>

#include "asm_ostream.hpp"
#include "asm_syntax.hpp"
#include "crab_utils/debug.hpp"
#include "crab_utils/num_big.hpp"
#include "spec_type_descriptors.hpp"

namespace crab {

class cfg_t;

// Node type for the CFG
class value_t final {
    friend class cfg_t;

  public:
    value_t(const value_t&) = delete;

    using label_vec_t = std::set<label_t>;
    using neighbour_const_iterator = label_vec_t::const_iterator;
    using neighbour_const_reverse_iterator = label_vec_t::const_reverse_iterator;

  private:
    label_t m_label;
    GuardedInstruction m_instruction;
    label_vec_t m_prev, m_next;

  public:
    explicit value_t(label_t _label) : m_label{std::move(_label)} {}

    ~value_t() = default;

    [[nodiscard]]
    label_t label() const {
        return m_label;
    }

    [[nodiscard]]
    GuardedInstruction& instruction() {
        return m_instruction;
    }

    [[nodiscard]]
    const GuardedInstruction& instruction() const {
        return m_instruction;
    }

    [[nodiscard]]
    std::pair<neighbour_const_iterator, neighbour_const_iterator> next_labels() const {
        return std::make_pair(m_next.begin(), m_next.end());
    }
    [[nodiscard]]
    std::pair<neighbour_const_reverse_iterator, neighbour_const_reverse_iterator> next_labels_reversed() const {
        return std::make_pair(m_next.rbegin(), m_next.rend());
    }

    [[nodiscard]]
    std::pair<neighbour_const_iterator, neighbour_const_iterator> prev_labels() const {
        return std::make_pair(m_prev.begin(), m_prev.end());
    }

    [[nodiscard]]
    const label_vec_t& next_labels_set() const {
        return m_next;
    }

    [[nodiscard]]
    const label_vec_t& prev_labels_set() const {
        return m_prev;
    }

    // Add a cfg_t edge from *this to b
    void operator>>(value_t& b) {
        assert(b.label() != label_t::entry);
        assert(this->label() != label_t::exit);
        m_next.insert(b.m_label);
        b.m_prev.insert(m_label);
    }

    // Remove a cfg_t edge from *this to b
    void operator-=(value_t& b) {
        m_next.erase(b.m_label);
        b.m_prev.erase(m_label);
    }

    [[nodiscard]]
    size_t in_degree() const {
        return m_prev.size();
    }

    [[nodiscard]]
    size_t out_degree() const {
        return m_next.size();
    }
};

/// Control-Flow Graph
class cfg_t final {
  public:
    using node_t = label_t; // for Bgl graphs

    using neighbour_const_iterator = value_t::neighbour_const_iterator;
    using neighbour_const_reverse_iterator = value_t::neighbour_const_reverse_iterator;

    using neighbour_const_range = boost::iterator_range<neighbour_const_iterator>;
    using neighbour_const_reverse_range = boost::iterator_range<neighbour_const_reverse_iterator>;

  private:
    using map_t = std::map<label_t, value_t>;
    using binding_t = map_t::value_type;

    struct get_label {
        label_t operator()(const binding_t& p) const { return p.second.label(); }
    };

  public:
    using iterator = map_t::iterator;
    using const_iterator = map_t::const_iterator;
    using label_iterator = boost::transform_iterator<get_label, map_t::iterator>;
    using const_label_iterator = boost::transform_iterator<get_label, map_t::const_iterator>;

  private:
    map_t m_map;

    using visited_t = std::set<label_t>;

  public:
    cfg_t() {
        m_map.emplace(entry_label(), entry_label());
        m_map.emplace(exit_label(), exit_label());
    }

    cfg_t(const cfg_t&) = delete;

    cfg_t(cfg_t&& o) noexcept : m_map(std::move(o.m_map)) {}

    ~cfg_t() = default;

    [[nodiscard]]
    label_t exit_label() const {
        return label_t::exit;
    }

    // --- Begin ikos fixpoint API

    [[nodiscard]]
    label_t entry_label() const {
        return label_t::entry;
    }

    [[nodiscard]]
    neighbour_const_range next_nodes(const label_t& _label) const {
        return boost::make_iterator_range(get_node(_label).next_labels());
    }

    [[nodiscard]]
    neighbour_const_reverse_range next_nodes_reversed(const label_t& _label) const {
        return boost::make_iterator_range(get_node(_label).next_labels_reversed());
    }

    [[nodiscard]]
    neighbour_const_range prev_nodes(const label_t& _label) const {
        return boost::make_iterator_range(get_node(_label).prev_labels());
    }

    value_t& get_node(const label_t& _label) {
        const auto it = m_map.find(_label);
        if (it == m_map.end()) {
            CRAB_ERROR("Basic block ", _label, " not found in the CFG: ");
        }
        return it->second;
    }

    const value_t& get_node(const label_t& _label) const {
        const auto it = m_map.find(_label);
        if (it == m_map.end()) {
            CRAB_ERROR("Basic block ", _label, " not found in the CFG: ", __LINE__);
        }
        return it->second;
    }

    GuardedInstruction& at(const label_t& _label) {
        const auto it = m_map.find(_label);
        if (it == m_map.end()) {
            CRAB_ERROR("Basic block ", _label, " not found in the CFG: ", __LINE__);
        }
        return it->second.instruction();
    }

    [[nodiscard]]
    const GuardedInstruction& at(const label_t& _label) const {
        const auto it = m_map.find(_label);
        if (it == m_map.end()) {
            CRAB_ERROR("Basic block ", _label, " not found in the CFG: ", __LINE__);
        }
        return it->second.instruction();
    }

    // --- End ikos fixpoint API

    value_t& insert_before(const label_t& next_label, const label_t& new_label, const Instruction& _ins) {
        value_t& res = insert(new_label, GuardedInstruction{.cmd = _ins});
        for (const label_t& prev : prev_nodes(next_label)) {
            get_node(prev) >> res;
            res >> get_node(next_label);
        }
        return res;
    }

    value_t& insert(const label_t& _label, const Instruction& _ins) {
        return insert(_label, GuardedInstruction{.cmd = _ins});
    }

    value_t& insert(const label_t& _label, GuardedInstruction&& _ins) {
        const auto it = m_map.find(_label);
        if (it != m_map.end()) {
            return it->second;
        }

        m_map.emplace(_label, _label);
        value_t& v = get_node(_label);
        v.m_instruction = std::move(_ins);
        return v;
    }

    void remove(const label_t& _label) {
        if (_label == entry_label()) {
            CRAB_ERROR("Cannot remove entry block");
        }

        if (_label == exit_label()) {
            CRAB_ERROR("Cannot remove exit block");
        }

        std::vector<std::pair<value_t*, value_t*>> dead_edges;
        auto& bb = get_node(_label);

        for (const auto& id : boost::make_iterator_range(bb.prev_labels())) {
            if (_label != id) {
                dead_edges.emplace_back(&get_node(id), &bb);
            }
        }

        for (const auto& id : boost::make_iterator_range(bb.next_labels())) {
            if (_label != id) {
                dead_edges.emplace_back(&bb, &get_node(id));
            }
        }

        for (const auto& p : dead_edges) {
            *p.first -= *p.second;
        }

        m_map.erase(_label);
    }

    //! return a begin iterator of basic_block_t's
    iterator begin() { return m_map.begin(); }

    //! return an end iterator of basic_block_t's
    iterator end() { return m_map.end(); }

    [[nodiscard]]
    const_iterator begin() const {
        return m_map.begin();
    }

    [[nodiscard]]
    const_iterator end() const {
        return m_map.end();
    }

    //! return a begin iterator of label_t's
    const_label_iterator label_begin() const { return boost::make_transform_iterator(m_map.begin(), get_label()); }

    //! return an end iterator of label_t's
    const_label_iterator label_end() const { return boost::make_transform_iterator(m_map.end(), get_label()); }

    //! return a begin iterator of label_t's
    [[nodiscard]]
    std::vector<label_t> labels() const {
        std::vector<label_t> res;
        res.reserve(m_map.size());
        for (const auto& p : m_map) {
            res.push_back(p.first);
        }
        return res;
    }

    [[nodiscard]]
    size_t size() const {
        return gsl::narrow<size_t>(std::distance(begin(), end()));
    }

    [[nodiscard]]
    std::vector<label_t> sorted_labels() const {
        std::vector<label_t> labels = this->labels();
        std::sort(labels.begin(), labels.end());
        return labels;
    }

    value_t& get_child(const label_t& b) {
        assert(has_one_child(b));
        const auto rng = next_nodes(b);
        return get_node(*rng.begin());
    }

    value_t& get_parent(const label_t& b) {
        assert(has_one_parent(b));
        const auto rng = prev_nodes(b);
        return get_node(*rng.begin());
    }

  private:
    // Helpers
    [[nodiscard]]
    bool has_one_child(const label_t& b) const {
        const auto rng = next_nodes(b);
        return std::distance(rng.begin(), rng.end()) == 1;
    }

    [[nodiscard]]
    bool has_one_parent(const label_t& b) const {
        const auto rng = prev_nodes(b);
        return std::distance(rng.begin(), rng.end()) == 1;
    }

    // mark reachable blocks from curId
    template <class AnyCfg>
    void mark_alive_blocks(label_t curId, AnyCfg& cfg_t, visited_t& visited) {
        if (visited.contains(curId)) {
            return;
        }
        visited.insert(curId);
        for (const auto& child : cfg_t.next_nodes(curId)) {
            mark_alive_blocks(child, cfg_t, visited);
        }
    }

    void remove_unreachable_blocks();
};

class basic_block_t final {
    friend class cfg_t;

  public:
    basic_block_t(const basic_block_t&) = delete;

    using label_vec_t = std::set<label_t>;
    using stmt_list_t = std::vector<GuardedInstruction*>;
    using iterator = stmt_list_t::iterator;
    using const_iterator = stmt_list_t::const_iterator;
    using reverse_iterator = stmt_list_t::reverse_iterator;
    using const_reverse_iterator = stmt_list_t::const_reverse_iterator;

  private:
    label_t m_label;
    stmt_list_t m_ts;

  public:
    static std::map<label_t, basic_block_t> collect_basic_blocks(cfg_t& cfg) {
        std::map<label_t, basic_block_t> res;

        std::set worklist(cfg.label_begin(), cfg.label_end());
        std::set<label_t> seen;
        while (!worklist.empty()) {
            label_t label = *worklist.begin();
            worklist.erase(label);
            if (seen.contains(label)) {
                continue;
            }
            seen.insert(label);

            const value_t& value = cfg.get_node(label);
            if (value.in_degree() == 1 && cfg.get_parent(label).out_degree() == 1) {
                continue;
            }
            res.emplace(label, label);
            basic_block_t& bb = res.at(label);
            while (value.out_degree() == 1) {
                value_t& next_value = cfg.get_child(label);

                if (&next_value == &value || next_value.in_degree() != 1) {
                    break;
                }
                if (next_value.label() == cfg.exit_label()) {
                    break;
                }
                worklist.erase(next_value.label());

                bb.m_ts.push_back(&next_value.instruction());

                // delete next_bb entirely
                // remove(next_value.label());
                seen.insert(next_value.label());
            }
        }
        return res;
    }

    void insert(GuardedInstruction* arg) {
        assert(label() != label_t::entry);
        assert(label() != label_t::exit);
        m_ts.push_back(arg);
    }

    /// Insert a GuardedInstruction at the front of the basic block.
    /// @note Cannot modify entry or exit blocks.
    void insert_front(GuardedInstruction* arg) {
        assert(label() != label_t::entry);
        assert(label() != label_t::exit);
        m_ts.insert(m_ts.begin(), arg);
    }

    explicit basic_block_t(label_t _label) : m_label(std::move(_label)) {}

    ~basic_block_t() = default;

    [[nodiscard]]
    label_t label() const {
        return m_label;
    }

    iterator begin() { return (m_ts.begin()); }
    iterator end() { return (m_ts.end()); }
    [[nodiscard]]
    const_iterator begin() const {
        return m_ts.begin();
    }
    [[nodiscard]]
    const_iterator end() const {
        return m_ts.end();
    }

    reverse_iterator rbegin() { return (m_ts.rbegin()); }
    reverse_iterator rend() { return (m_ts.rend()); }
    [[nodiscard]]
    const_reverse_iterator rbegin() const {
        return m_ts.rbegin();
    }
    [[nodiscard]]
    const_reverse_iterator rend() const {
        return m_ts.rend();
    }

    [[nodiscard]]
    size_t size() const {
        return gsl::narrow<size_t>(std::distance(begin(), end()));
    }

    // insert all statements of other at the back
    void move_back(basic_block_t& other) {
        m_ts.reserve(m_ts.size() + other.m_ts.size());
        std::ranges::move(other.m_ts, std::back_inserter(m_ts));
    }

    void swap_instructions(stmt_list_t& ts) { std::swap(m_ts, ts); }
};

// Viewing basic_block_t with all statements reversed. Useful for
// backward analysis.
class basic_block_rev_t final {
  public:
    using iterator = basic_block_t::reverse_iterator;
    using const_iterator = basic_block_t::const_reverse_iterator;

  public:
    basic_block_t& _bb;

    explicit basic_block_rev_t(basic_block_t& bb) : _bb(bb) {}

    [[nodiscard]]
    label_t label() const {
        return _bb.label();
    }

    iterator begin() { return _bb.rbegin(); }

    iterator end() { return _bb.rend(); }

    [[nodiscard]]
    const_iterator begin() const {
        return _bb.rbegin();
    }

    [[nodiscard]]
    const_iterator end() const {
        return _bb.rend();
    }

    [[nodiscard]]
    std::size_t size() const {
        return gsl::narrow<size_t>(std::distance(begin(), end()));
    }
};

inline void cfg_t::remove_unreachable_blocks() {
    visited_t alive, dead;
    mark_alive_blocks(entry_label(), *this, alive);

    for (const auto& label : labels()) {
        if (!alive.contains(label)) {
            dead.insert(label);
        }
    }

    if (dead.contains(exit_label())) {
        CRAB_ERROR("Exit block must be reachable");
    }
    for (const auto& _label : dead) {
        remove(_label);
    }
}

} // end namespace crab

using crab::basic_block_t;
using crab::cfg_t;

std::vector<std::string> stats_headers();

std::map<std::string, int> collect_stats(const cfg_t&);

struct prepare_cfg_options {
    /// When true, verifies that the program terminates.
    bool check_for_termination = false;
    /// When true, ensures the program has a valid exit block.
    bool must_have_exit = true;
};

cfg_t prepare_cfg(const InstructionSeq& prog, const program_info& info, const prepare_cfg_options& options);

void explicate_assertions(cfg_t& cfg, const program_info& info);
std::vector<Assertion> get_assertions(Instruction ins, const program_info& info, const std::optional<label_t>& label);

void print_dot(const cfg_t& cfg, std::ostream& out);
void print_dot(const cfg_t& cfg, const std::string& outfile);

std::ostream& operator<<(std::ostream& o, const basic_block_t& bb);
std::ostream& operator<<(std::ostream& o, const crab::value_t& value);
std::ostream& operator<<(std::ostream& o, const cfg_t& cfg);
