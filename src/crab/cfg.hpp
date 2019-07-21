#pragma once

/*
 * Build a CFG to interface with the abstract domains and fixpoint
 * iterators.
 *
 * All the CFG statements are strongly typed. However, only variables
 * need to be typed. The types of constants can be inferred from the
 * context since they always appear together with at least one
 * variable. Types form a **flat** lattice consisting of:
 *
 * - integers,
 * - array of integers,
 *
 * Crab CFG supports the modelling of:
 *
 *   - arithmetic operations over integers or reals,
 *   - boolean operations,
 *   - C-like pointers,
 *   - uni-dimensional arrays of booleans, integers or pointers
 *     (useful for C-like arrays and heap abstractions),
 *   - and functions
 *
 * Important notes:
 *
 * - Objects of the class cfg_t are not copyable. Instead, we provide a
 *   class cfg_ref_t that wraps cfg_t references into copyable and
 *   assignable objects.
 *
 */
#include <memory>
#include <unordered_map>
#include <unordered_set>

#include <variant>

#include <boost/iterator/transform_iterator.hpp>
#include <boost/range/iterator_range.hpp>

#include "crab/crab_syntax.hpp"
#include "crab/bignums.hpp"
#include "crab/discrete_domains.hpp"
#include "crab/interval.hpp"
#include "crab/linear_constraints.hpp"
#include "crab/types.hpp"

namespace crab {

class cfg_t;

class basic_block_t final {
    basic_block_t(const basic_block_t&) = delete;

    friend class cfg_t;

  private:
    using bb_id_set_t = std::vector<basic_block_label_t>;
    using stmt_list_t = std::vector<new_statement_t>;

  public:
    // -- iterators

    using succ_iterator = bb_id_set_t::iterator;
    using const_succ_iterator = bb_id_set_t::const_iterator;
    using pred_iterator = succ_iterator;
    using const_pred_iterator = const_succ_iterator;
    using iterator = stmt_list_t::iterator;
    using const_iterator = stmt_list_t::const_iterator;
    using reverse_iterator = stmt_list_t::reverse_iterator;
    using const_reverse_iterator = stmt_list_t::const_reverse_iterator;

    // -- statements

  private:
    basic_block_label_t m_bb_id;
    stmt_list_t m_ts;
    bb_id_set_t m_prev, m_next;

    void insert_adjacent(bb_id_set_t& c, basic_block_label_t e) {
        if (std::find(c.begin(), c.end(), e) == c.end()) {
            c.push_back(e);
        }
    }

    void remove_adjacent(bb_id_set_t& c, basic_block_label_t e) {
        if (std::find(c.begin(), c.end(), e) != c.end()) {
            c.erase(std::remove(c.begin(), c.end(), e), c.end());
        }
    }

    basic_block_t(const basic_block_label_t bb_id) : m_bb_id(bb_id) {}

    basic_block_t(basic_block_t&& bb)
        : m_bb_id(bb.label()), m_ts(std::move(bb.m_ts)), m_prev(bb.m_prev), m_next(bb.m_next) {}

    template <typename T, typename... Args>
    void insert(Args&&... args) {
        m_ts.emplace_back(T{std::forward<Args>(args)...});
    }

  public:
    ~basic_block_t() = default;

    basic_block_label_t label() const { return m_bb_id; }

    std::string name() const { return m_bb_id; }

    iterator begin() { return (m_ts.begin()); }
    iterator end() { return (m_ts.end()); }
    const_iterator begin() const { return (m_ts.begin()); }
    const_iterator end() const { return (m_ts.end()); }

    reverse_iterator rbegin() { return (m_ts.rbegin()); }
    reverse_iterator rend() { return (m_ts.rend()); }
    const_reverse_iterator rbegin() const { return (m_ts.rbegin()); }
    const_reverse_iterator rend() const { return (m_ts.rend()); }

    size_t size() const { return std::distance(begin(), end()); }

    std::pair<succ_iterator, succ_iterator> next_blocks() { return std::make_pair(m_next.begin(), m_next.end()); }

    std::pair<pred_iterator, pred_iterator> prev_blocks() { return std::make_pair(m_prev.begin(), m_prev.end()); }

    std::pair<const_succ_iterator, const_succ_iterator> next_blocks() const {
        return std::make_pair(m_next.begin(), m_next.end());
    }

    std::pair<const_pred_iterator, const_pred_iterator> prev_blocks() const {
        return std::make_pair(m_prev.begin(), m_prev.end());
    }

    // Add a cfg_t edge from *this to b
    void operator>>(basic_block_t& b) {
        insert_adjacent(m_next, b.m_bb_id);
        insert_adjacent(b.m_prev, m_bb_id);
    }

    // Remove a cfg_t edge from *this to b
    void operator-=(basic_block_t& b) {
        remove_adjacent(m_next, b.m_bb_id);
        remove_adjacent(b.m_prev, m_bb_id);
    }

    // insert all statements of other at the back
    void move_back(basic_block_t& other) {
        m_ts.reserve(m_ts.size() + other.m_ts.size());
        std::move(other.m_ts.begin(), other.m_ts.end(), std::back_inserter(m_ts));
    }

    void write(crab_os& o) const {
        o << m_bb_id << ":\n";
        for (auto const& s : *this) {
            o << "  " << s << ";\n";
        }
        std::pair<const_succ_iterator, const_succ_iterator> p = next_blocks();
        const_succ_iterator it = p.first;
        const_succ_iterator et = p.second;
        if (it != et) {
            o << "  "
              << "goto ";
            for (; it != et;) {
                o << *it;
                ++it;
                if (it == et) {
                    o << ";";
                } else {
                    o << ",";
                }
            }
        }
        o << "\n";
    }

    // for gdb
    void dump() const { write(errs()); }

    /// To build statements

    void add(variable_t lhs, variable_t op1, variable_t op2) { insert<binary_op_t>(lhs, BINOP::ADD, op1, op2); }

    void add(variable_t lhs, variable_t op1, number_t op2) { insert<binary_op_t>(lhs, BINOP::ADD, op1, op2); }

    void sub(variable_t lhs, variable_t op1, variable_t op2) { insert<binary_op_t>(lhs, BINOP::SUB, op1, op2); }

    void sub(variable_t lhs, variable_t op1, number_t op2) { insert<binary_op_t>(lhs, BINOP::SUB, op1, op2); }

    void mul(variable_t lhs, variable_t op1, variable_t op2) { insert<binary_op_t>(lhs, BINOP::MUL, op1, op2); }

    void mul(variable_t lhs, variable_t op1, number_t op2) { insert<binary_op_t>(lhs, BINOP::MUL, op1, op2); }

    // signed division
    void div(variable_t lhs, variable_t op1, variable_t op2) { insert<binary_op_t>(lhs, BINOP::SDIV, op1, op2); }

    void div(variable_t lhs, variable_t op1, number_t op2) { insert<binary_op_t>(lhs, BINOP::SDIV, op1, op2); }

    // unsigned division
    void udiv(variable_t lhs, variable_t op1, variable_t op2) { insert<binary_op_t>(lhs, BINOP::UDIV, op1, op2); }

    void udiv(variable_t lhs, variable_t op1, number_t op2) { insert<binary_op_t>(lhs, BINOP::UDIV, op1, op2); }

    // signed rem
    void rem(variable_t lhs, variable_t op1, variable_t op2) { insert<binary_op_t>(lhs, BINOP::SREM, op1, op2); }

    void rem(variable_t lhs, variable_t op1, number_t op2) { insert<binary_op_t>(lhs, BINOP::SREM, op1, op2); }

    // unsigned rem
    void urem(variable_t lhs, variable_t op1, variable_t op2) { insert<binary_op_t>(lhs, BINOP::UREM, op1, op2); }

    void urem(variable_t lhs, variable_t op1, number_t op2) { insert<binary_op_t>(lhs, BINOP::UREM, op1, op2); }

    void bitwise_and(variable_t lhs, variable_t op1, variable_t op2) { insert<binary_op_t>(lhs, BINOP::AND, op1, op2); }

    void bitwise_and(variable_t lhs, variable_t op1, number_t op2) { insert<binary_op_t>(lhs, BINOP::AND, op1, op2); }

    void bitwise_or(variable_t lhs, variable_t op1, variable_t op2) { insert<binary_op_t>(lhs, BINOP::OR, op1, op2); }

    void bitwise_or(variable_t lhs, variable_t op1, number_t op2) { insert<binary_op_t>(lhs, BINOP::OR, op1, op2); }

    void bitwise_xor(variable_t lhs, variable_t op1, variable_t op2) { insert<binary_op_t>(lhs, BINOP::XOR, op1, op2); }

    void bitwise_xor(variable_t lhs, variable_t op1, number_t op2) { insert<binary_op_t>(lhs, BINOP::XOR, op1, op2); }

    void shl(variable_t lhs, variable_t op1, variable_t op2) { insert<binary_op_t>(lhs, BINOP::SHL, op1, op2); }

    void shl(variable_t lhs, variable_t op1, number_t op2) { insert<binary_op_t>(lhs, BINOP::SHL, op1, op2); }

    void lshr(variable_t lhs, variable_t op1, variable_t op2) { insert<binary_op_t>(lhs, BINOP::LSHR, op1, op2); }

    void lshr(variable_t lhs, variable_t op1, number_t op2) { insert<binary_op_t>(lhs, BINOP::LSHR, op1, op2); }

    void ashr(variable_t lhs, variable_t op1, variable_t op2) { insert<binary_op_t>(lhs, BINOP::ASHR, op1, op2); }

    void ashr(variable_t lhs, variable_t op1, number_t op2) { insert<binary_op_t>(lhs, BINOP::ASHR, op1, op2); }

    void assign(variable_t lhs, linear_expression_t rhs) { insert<assign_t>(lhs, rhs); }

    void assume(linear_constraint_t cst) { insert<assume_t>(cst); }

    void havoc(variable_t lhs) { insert<havoc_t>(lhs); }

    void select(variable_t lhs, variable_t v, linear_expression_t e1, linear_expression_t e2) {
        linear_constraint_t cond(exp_gte(v, 1));
        insert<select_t>(lhs, cond, e1, e2);
    }

    void select(variable_t lhs, linear_constraint_t cond, linear_expression_t e1, linear_expression_t e2) {
        insert<select_t>(lhs, cond, e1, e2);
    }

    void assertion(linear_constraint_t cst, debug_info di = {}) { insert<assert_t>(cst, di); }

    void array_store(variable_t arr, linear_expression_t idx, linear_expression_t v, linear_expression_t elem_size) {
        insert<array_store_t>(arr, elem_size, idx, idx, v);
    }

    void array_store_range(variable_t arr, linear_expression_t lb_idx, linear_expression_t ub_idx,
                           linear_expression_t v, linear_expression_t elem_size) {
        insert<array_store_t>(arr, elem_size, lb_idx, ub_idx, v);
    }

    void array_load(variable_t lhs, variable_t arr, linear_expression_t idx, linear_expression_t elem_size) {
        insert<array_load_t>(lhs, arr, elem_size, idx);
    }

    friend crab_os& operator<<(crab_os& o, const basic_block_t& b) {
        b.write(o);
        return o;
    }
};

// Viewing basic_block_t with all statements reversed. Useful for
// backward analysis.
class basic_block_rev_t final {
  public:
    using succ_iterator = basic_block_t::succ_iterator;
    using const_succ_iterator = basic_block_t::const_succ_iterator;
    using pred_iterator = succ_iterator;
    using const_pred_iterator = const_succ_iterator;

    using iterator = basic_block_t::reverse_iterator;
    using const_iterator = basic_block_t::const_reverse_iterator;

  private:
  public:
    basic_block_t& _bb;

    basic_block_rev_t(basic_block_t& bb) : _bb(bb) {}

    basic_block_label_t label() const { return _bb.label(); }

    std::string name() const { return _bb.name(); }

    iterator begin() { return _bb.rbegin(); }

    iterator end() { return _bb.rend(); }

    const_iterator begin() const { return _bb.rbegin(); }

    const_iterator end() const { return _bb.rend(); }

    std::size_t size() const { return std::distance(begin(), end()); }

    std::pair<succ_iterator, succ_iterator> next_blocks() { return _bb.prev_blocks(); }

    std::pair<pred_iterator, pred_iterator> prev_blocks() { return _bb.next_blocks(); }

    std::pair<const_succ_iterator, const_succ_iterator> next_blocks() const { return _bb.prev_blocks(); }

    std::pair<const_pred_iterator, const_pred_iterator> prev_blocks() const { return _bb.next_blocks(); }

    void write(crab_os& o) const {
        o << name() << ":\n";
        for (auto const& s : *this) {
            o << "  " << s << ";\n";
        }
        o << "--> [";
        for (auto const& n : boost::make_iterator_range(next_blocks())) {
            o << n << ";";
        }
        o << "]\n";
    }

    // for gdb
    void dump() const { write(errs()); }

    friend crab_os& operator<<(crab_os& o, const basic_block_rev_t& b) {
        b.write(o);
        return o;
    }
};

class cfg_t final {
  public:
    using node_t = basic_block_label_t; // for Bgl graphs

    using succ_iterator = basic_block_t::succ_iterator;
    using pred_iterator = basic_block_t::pred_iterator;
    using const_succ_iterator = basic_block_t::const_succ_iterator;
    using const_pred_iterator = basic_block_t::const_pred_iterator;

    using succ_range = boost::iterator_range<succ_iterator>;
    using pred_range = boost::iterator_range<pred_iterator>;
    using const_succ_range = boost::iterator_range<const_succ_iterator>;
    using const_pred_range = boost::iterator_range<const_pred_iterator>;

  private:
    using basic_block_map_t = std::unordered_map<basic_block_label_t, std::unique_ptr<basic_block_t>>;
    using binding_t = basic_block_map_t::value_type;

    struct get_ref : public std::unary_function<binding_t, basic_block_t> {
        get_ref() {}
        basic_block_t& operator()(const binding_t& p) const { return *(p.second); }
    };

    struct get_label : public std::unary_function<binding_t, basic_block_label_t> {
        get_label() {}
        basic_block_label_t operator()(const binding_t& p) const { return p.second->label(); }
    };

  public:
    using iterator = boost::transform_iterator<get_ref, basic_block_map_t::iterator>;
    using const_iterator = boost::transform_iterator<get_ref, basic_block_map_t::const_iterator>;
    using label_iterator = boost::transform_iterator<get_label, basic_block_map_t::iterator>;
    using const_label_iterator = boost::transform_iterator<get_label, basic_block_map_t::const_iterator>;

    using var_iterator = std::vector<varname_t>::iterator;
    using const_var_iterator = std::vector<varname_t>::const_iterator;

  private:
    basic_block_label_t m_entry;
    std::optional<basic_block_label_t> m_exit;
    basic_block_map_t m_blocks;

    using visited_t = std::unordered_set<basic_block_label_t>;
    template <typename T>
    void dfs_rec(basic_block_label_t curId, visited_t& visited, T f) const {
        if (!visited.insert(curId).second)
            return;

        const auto& cur = get_node(curId);
        f(cur);
        for (auto const n : boost::make_iterator_range(cur.next_blocks())) {
            dfs_rec(n, visited, f);
        }
    }

    template <typename T>
    void dfs(T f) const {
        visited_t visited;
        dfs_rec(m_entry, visited, f);
    }

    struct print_block {
        crab_os& m_o;
        print_block(crab_os& o) : m_o(o) {}
        void operator()(const basic_block_t& B) { B.write(m_o); }
    };

  public:
    cfg_t(basic_block_label_t entry) : m_entry(entry), m_exit(std::nullopt) {
        m_blocks.emplace(m_entry, new basic_block_t(m_entry));
    }

    cfg_t(basic_block_label_t entry, basic_block_label_t exit) : m_entry(entry), m_exit(exit) {
        m_blocks.emplace(m_entry, new basic_block_t(m_entry));
    }

    cfg_t(const cfg_t&) = delete;

    cfg_t(cfg_t&& o) : m_entry(o.m_entry), m_exit(o.m_exit), m_blocks(std::move(o.m_blocks)) {}

    ~cfg_t() = default;

    bool has_exit() const { return (bool)m_exit; }

    basic_block_label_t exit() const {
        if (has_exit())
            return *m_exit;
        CRAB_ERROR("cfg_t does not have an exit block");
    }

    //! set method to mark the exit block after the cfg_t has been
    //! created.
    void set_exit(basic_block_label_t exit) { m_exit = exit; }

    // --- Begin ikos fixpoint API

    basic_block_label_t entry() const { return m_entry; }

    const_succ_range next_nodes(basic_block_label_t bb_id) const {
        const auto& b = get_node(bb_id);
        return boost::make_iterator_range(b.next_blocks());
    }

    const_pred_range prev_nodes(basic_block_label_t bb_id) const {
        const auto& b = get_node(bb_id);
        return boost::make_iterator_range(b.prev_blocks());
    }

    succ_range next_nodes(basic_block_label_t bb_id) {
        auto& b = get_node(bb_id);
        return boost::make_iterator_range(b.next_blocks());
    }

    pred_range prev_nodes(basic_block_label_t bb_id) {
        auto& b = get_node(bb_id);
        return boost::make_iterator_range(b.prev_blocks());
    }

    basic_block_t& get_node(basic_block_label_t bb_id) {
        auto it = m_blocks.find(bb_id);
        if (it == m_blocks.end()) {
            CRAB_ERROR("Basic block ", bb_id, " not found in the CFG: ", __LINE__);
        }

        return *(it->second);
    }

    const basic_block_t& get_node(basic_block_label_t bb_id) const {
        auto it = m_blocks.find(bb_id);
        if (it == m_blocks.end()) {
            CRAB_ERROR("Basic block ", bb_id, " not found in the CFG: ", __LINE__);
        }

        return *(it->second);
    }

    // --- End ikos fixpoint API

    basic_block_t& insert(basic_block_label_t bb_id);

    void remove(basic_block_label_t bb_id);

    //! return a begin iterator of basic_block_t's
    iterator begin() { return boost::make_transform_iterator(m_blocks.begin(), get_ref()); }

    //! return an end iterator of basic_block_t's
    iterator end() { return boost::make_transform_iterator(m_blocks.end(), get_ref()); }

    const_iterator begin() const { return boost::make_transform_iterator(m_blocks.begin(), get_ref()); }

    const_iterator end() const { return boost::make_transform_iterator(m_blocks.end(), get_ref()); }

    //! return a begin iterator of basic_block_label_t's
    label_iterator label_begin() { return boost::make_transform_iterator(m_blocks.begin(), get_label()); }

    //! return an end iterator of basic_block_label_t's
    label_iterator label_end() { return boost::make_transform_iterator(m_blocks.end(), get_label()); }

    const_label_iterator label_begin() const { return boost::make_transform_iterator(m_blocks.begin(), get_label()); }

    const_label_iterator label_end() const { return boost::make_transform_iterator(m_blocks.end(), get_label()); }

    size_t size() const { return std::distance(begin(), end()); }

    void write(crab_os& o) const {
        print_block f(o);
        dfs(f);
    }

    // for gdb
    void dump() const {
        errs() << "number_t of basic blocks=" << size() << "\n";
        for (auto& bb : boost::make_iterator_range(begin(), end())) {
            bb.dump();
        }
    }

    friend crab_os& operator<<(crab_os& o, const cfg_t& cfg) {
        cfg.write(o);
        return o;
    }

    void simplify() {
        merge_blocks();
        remove_unreachable_blocks();
        remove_useless_blocks();
        // after removing useless blocks there can be opportunities to
        // merge more blocks.
        merge_blocks();
        merge_blocks();
    }

  private:
    ////
    // Trivial cfg_t simplifications
    // TODO: move to transform directory
    ////

    // Helpers
    bool has_one_child(basic_block_label_t b) const {
        auto rng = next_nodes(b);
        return (std::distance(rng.begin(), rng.end()) == 1);
    }

    bool has_one_parent(basic_block_label_t b) const {
        auto rng = prev_nodes(b);
        return (std::distance(rng.begin(), rng.end()) == 1);
    }

    basic_block_t& get_child(basic_block_label_t b) {
        assert(has_one_child(b));
        auto rng = next_nodes(b);
        return get_node(*(rng.begin()));
    }

    basic_block_t& get_parent(basic_block_label_t b) {
        assert(has_one_parent(b));
        auto rng = prev_nodes(b);
        return get_node(*(rng.begin()));
    }

    void merge_blocks_rec(basic_block_label_t curId, visited_t& visited) {
        if (!visited.insert(curId).second)
            return;

        auto& cur = get_node(curId);

        if (has_one_child(curId) && has_one_parent(curId)) {
            auto& parent = get_parent(curId);
            auto& child = get_child(curId);

            // Merge with its parent if it's its only child.
            if (has_one_child(parent.label())) {
                // move all statements from cur to parent
                parent.move_back(cur);
                visited.erase(curId);
                remove(curId);
                parent >> child;
                merge_blocks_rec(child.label(), visited);
                return;
            }
        }

        for (auto n : boost::make_iterator_range(cur.next_blocks())) {
            merge_blocks_rec(n, visited);
        }
    }

    // Merges a basic block into its predecessor if there is only one
    // and the predecessor only has one successor.
    void merge_blocks() {
        visited_t visited;
        merge_blocks_rec(entry(), visited);
    }

    // mark reachable blocks from curId
    template <class AnyCfg>
    void mark_alive_blocks(basic_block_label_t curId, AnyCfg& cfg_t, visited_t& visited) {
        if (visited.count(curId) > 0)
            return;
        visited.insert(curId);
        for (auto child : cfg_t.next_nodes(curId)) {
            mark_alive_blocks(child, cfg_t, visited);
        }
    }

    void remove_unreachable_blocks();

    // remove blocks that cannot reach the exit block
    void remove_useless_blocks();
};

// A lightweight object that wraps a reference to a CFG into a
// copyable, assignable object.
class cfg_ref_t final {
  public:
    // cfg_t's typedefs
    using node_t = cfg_t::node_t;

    using succ_iterator = cfg_t::succ_iterator;
    using pred_iterator = cfg_t::pred_iterator;
    using const_succ_iterator = cfg_t::const_succ_iterator;
    using const_pred_iterator = cfg_t::const_pred_iterator;
    using succ_range = cfg_t::succ_range;
    using pred_range = cfg_t::pred_range;
    using const_succ_range = cfg_t::const_succ_range;
    using const_pred_range = cfg_t::const_pred_range;
    using iterator = cfg_t::iterator;
    using const_iterator = cfg_t::const_iterator;
    using label_iterator = cfg_t::label_iterator;
    using const_label_iterator = cfg_t::const_label_iterator;
    using var_iterator = cfg_t::var_iterator;
    using const_var_iterator = cfg_t::const_var_iterator;

  private:
    std::reference_wrapper<cfg_t> _ref;

    const cfg_t& get() const { return _ref; }

    cfg_t& get() { return _ref; }

  public:
    cfg_ref_t(cfg_t& cfg) : _ref(std::ref(cfg)) {}

    basic_block_label_t entry() const { return get().entry(); }

    const_succ_range next_nodes(basic_block_label_t bb) const { return get().next_nodes(bb); }

    const_pred_range prev_nodes(basic_block_label_t bb) const { return get().prev_nodes(bb); }

    succ_range next_nodes(basic_block_label_t bb) { return get().next_nodes(bb); }

    pred_range prev_nodes(basic_block_label_t bb) { return get().prev_nodes(bb); }

    basic_block_t& get_node(basic_block_label_t bb) { return get().get_node(bb); }

    const basic_block_t& get_node(basic_block_label_t bb) const { return get().get_node(bb); }

    size_t size() const { return get().size(); }

    iterator begin() { return get().begin(); }

    iterator end() { return get().end(); }

    const_iterator begin() const { return get().begin(); }

    const_iterator end() const { return get().end(); }

    label_iterator label_begin() { return get().label_begin(); }

    label_iterator label_end() { return get().label_end(); }

    const_label_iterator label_begin() const { return get().label_begin(); }

    const_label_iterator label_end() const { return get().label_end(); }

    bool has_exit() const { return get().has_exit(); }

    basic_block_label_t exit() const { return get().exit(); }

    friend crab_os& operator<<(crab_os& o, const cfg_ref_t& cfg) { return o << cfg.get(); }

    // for gdb
    void dump() const { get().dump(); }

    void simplify() { get().simplify(); }
};

// Viewing a cfg_t with all edges and block statements
// reversed. Useful for backward analysis.
class cfg_rev_t final {
  public:
    using node_t = basic_block_label_t; // for Bgl graphs

    using pred_range = cfg_t::succ_range;
    using succ_range = cfg_t::pred_range;
    using const_pred_range = cfg_t::const_succ_range;
    using const_succ_range = cfg_t::const_pred_range;

    // For BGL
    using succ_iterator = basic_block_t::succ_iterator;
    using pred_iterator = basic_block_t::pred_iterator;
    using const_succ_iterator = basic_block_t::const_succ_iterator;
    using const_pred_iterator = basic_block_t::const_pred_iterator;

  private:
    struct getRev : public std::unary_function<basic_block_t, basic_block_rev_t> {
        const std::unordered_map<basic_block_label_t, basic_block_rev_t>& _rev_bbs;

        getRev(const std::unordered_map<basic_block_label_t, basic_block_rev_t>& rev_bbs) : _rev_bbs(rev_bbs) {}

        const basic_block_rev_t& operator()(basic_block_t& bb) const {
            auto it = _rev_bbs.find(bb.label());
            if (it != _rev_bbs.end())
                return it->second;
            CRAB_ERROR("Basic block ", bb.label(), " not found in the CFG: ", __LINE__);
        }
    };

    using visited_t = std::unordered_set<basic_block_label_t>;

    template <typename T>
    void dfs_rec(basic_block_label_t curId, visited_t& visited, T f) const {
        if (!visited.insert(curId).second)
            return;
        f(get_node(curId));
        for (auto const n : next_nodes(curId)) {
            dfs_rec(n, visited, f);
        }
    }

    template <typename T>
    void dfs(T f) const {
        visited_t visited;
        dfs_rec(entry(), visited, f);
    }

    struct print_block {
        crab_os& m_o;
        print_block(crab_os& o) : m_o(o) {}
        void operator()(const basic_block_rev_t& B) { B.write(m_o); }
    };

  public:
    using iterator = boost::transform_iterator<getRev, cfg_t::iterator>;
    using const_iterator = boost::transform_iterator<getRev, cfg_t::const_iterator>;
    using label_iterator = cfg_t::label_iterator;
    using const_label_iterator = cfg_t::const_label_iterator;
    using var_iterator = cfg_t::var_iterator;
    using const_var_iterator = cfg_t::const_var_iterator;

  private:
    cfg_t& _cfg;
    std::unordered_map<basic_block_label_t, basic_block_rev_t> _rev_bbs;

  public:
    cfg_rev_t(cfg_t& cfg) : _cfg(cfg) {
        // Create basic_block_rev_t from basic_block_t objects
        // Note that basic_block_rev_t is also a view of basic_block_t so it
        // doesn't modify basic_block_t objects.
        for (auto& bb : cfg) {
            _rev_bbs.emplace(bb.label(), bb);
        }
    }

    cfg_rev_t(const cfg_rev_t& o) : _cfg(o._cfg), _rev_bbs(o._rev_bbs) {}

    cfg_rev_t(cfg_rev_t&& o) : _cfg(o._cfg), _rev_bbs(std::move(o._rev_bbs)) {}

    basic_block_label_t entry() const {
        if (!_cfg.has_exit())
            CRAB_ERROR("Entry not found!");
        return _cfg.exit();
    }

    const_succ_range next_nodes(basic_block_label_t bb) const { return _cfg.prev_nodes(bb); }

    const_pred_range prev_nodes(basic_block_label_t bb) const { return _cfg.next_nodes(bb); }

    succ_range next_nodes(basic_block_label_t bb) { return _cfg.prev_nodes(bb); }

    pred_range prev_nodes(basic_block_label_t bb) { return _cfg.next_nodes(bb); }

    basic_block_rev_t& get_node(basic_block_label_t bb_id) {
        auto it = _rev_bbs.find(bb_id);
        if (it == _rev_bbs.end())
            CRAB_ERROR("Basic block ", bb_id, " not found in the CFG: ", __LINE__);
        return it->second;
    }

    const basic_block_rev_t& get_node(basic_block_label_t bb_id) const {
        auto it = _rev_bbs.find(bb_id);
        if (it == _rev_bbs.end())
            CRAB_ERROR("Basic block ", bb_id, " not found in the CFG: ", __LINE__);
        return it->second;
    }

    iterator begin() { return boost::make_transform_iterator(_cfg.begin(), getRev(_rev_bbs)); }

    iterator end() { return boost::make_transform_iterator(_cfg.end(), getRev(_rev_bbs)); }

    const_iterator begin() const { return boost::make_transform_iterator(_cfg.begin(), getRev(_rev_bbs)); }

    const_iterator end() const { return boost::make_transform_iterator(_cfg.end(), getRev(_rev_bbs)); }

    label_iterator label_begin() { return _cfg.label_begin(); }

    label_iterator label_end() { return _cfg.label_end(); }

    const_label_iterator label_begin() const { return _cfg.label_begin(); }

    const_label_iterator label_end() const { return _cfg.label_end(); }

    bool has_exit() const { return true; }

    basic_block_label_t exit() const { return _cfg.entry(); }

    void write(crab_os& o) const {
        print_block f(o);
        dfs(f);
    }

    friend crab_os& operator<<(crab_os& o, const cfg_rev_t& cfg_t) {
        cfg_t.write(o);
        return o;
    }

    void simplify() {}
};

void type_check(const cfg_ref_t& cfg_t);

} // end namespace crab
