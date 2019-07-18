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
 * - booleans,
 * - integers,
 * - reals,
 * - pointers,
 * - array of booleans,
 * - array of integers,
 * - array of reals, and
 * - array of pointers.
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
 * Limitations:
 *
 * - The CFG language does not allow to express floating point
 *   operations.
 *
 */

#include <boost/iterator/indirect_iterator.hpp>
#include <boost/iterator/transform_iterator.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/unordered_map.hpp>
#include <boost/unordered_set.hpp>

#include "crab/bignums.hpp"
#include "crab/discrete_domains.hpp"
#include "crab/interval.hpp"
#include "crab/linear_constraints.hpp"
#include "crab/types.hpp"

#include <functional> // for wrapper_reference

namespace crab {

// To convert a basic block label to a string
inline std::string get_label_str(std::string e) { return e; };

enum stmt_code {
    UNDEF = 0,
    // numerical
    BIN_OP = 20,
    ASSIGN = 21,
    ASSUME = 22,
    UNREACH = 23,
    SELECT = 24,
    ASSERT = 25,
    // arrays
    ARR_INIT = 30,
    ARR_STORE = 31,
    ARR_LOAD = 32,
    ARR_ASSIGN = 33,
    // integers/arrays/pointers/boolean
    HAVOC = 60,
    // casts
    INT_CAST = 80
};

class live_t {
  private:
    using live_set_t = std::vector<variable_t>;

  public:
    using const_use_iterator = typename live_set_t::const_iterator;
    using const_def_iterator = typename live_set_t::const_iterator;

  private:
    live_set_t m_uses;
    live_set_t m_defs;

    void add(live_set_t& s, variable_t v) {
        auto it = find(s.begin(), s.end(), v);
        if (it == s.end())
            s.push_back(v);
    }

  public:
    void add_use(const variable_t v) { add(m_uses, v); }
    void add_def(const variable_t v) { add(m_defs, v); }

    const_use_iterator uses_begin() const { return m_uses.begin(); }
    const_use_iterator uses_end() const { return m_uses.end(); }
    const_use_iterator defs_begin() const { return m_defs.begin(); }
    const_use_iterator defs_end() const { return m_defs.end(); }

    size_t num_uses() const { return m_uses.size(); }
    size_t num_defs() const { return m_defs.size(); }

    friend crab_os& operator<<(crab_os& o, const live_t& live) {
        o << "Use={";
        for (auto const& v : boost::make_iterator_range(live.uses_begin(), live.uses_end()))
            o << v << ",";
        o << "} Def={";
        for (auto const& v : boost::make_iterator_range(live.defs_begin(), live.defs_end()))
            o << v << ",";
        o << "}";
        return o;
    }
};

struct debug_info {

    std::string m_file;
    int m_line;
    int m_col;

    debug_info() : m_file(""), m_line(-1), m_col(-1) {}

    debug_info(std::string file, unsigned line, unsigned col) : m_file(file), m_line(line), m_col(col) {}

    bool operator<(const debug_info& other) const {
        return (m_file < other.m_file && m_line < other.m_line && m_col < other.m_col);
    }

    bool operator==(const debug_info& other) const {
        return (m_file == other.m_file && m_line == other.m_line && m_col == other.m_col);
    }

    bool has_debug() const { return ((m_file != "") && (m_line >= 0) && (m_col >= 0)); }

    void write(crab_os& o) const {
        o << "File  : " << m_file << "\n"
          << "Line  : " << m_line << "\n"
          << "Column: " << m_col << "\n";
    }
};

inline crab_os& operator<<(crab_os& o, const debug_info& l) {
    l.write(o);
    return o;
}

class basic_block_t;
class basic_block_rev_t;

class binary_op_t;
class assign_t;
class assume_t;
class select_t;
class assert_t;
class int_cast_t;
class unreachable_t;
class havoc_t;
class array_init_t;
class array_store_t;
class array_load_t;
class array_assign_t;

struct statement_visitor {
    using number_t = number_t;
    using varname_t = varname_t;

    virtual void visit(binary_op_t&){};
    virtual void visit(assign_t&){};
    virtual void visit(assume_t&){};
    virtual void visit(select_t&){};
    virtual void visit(assert_t&){};
    virtual void visit(int_cast_t&){};
    virtual void visit(unreachable_t&){};
    virtual void visit(havoc_t&){};
    virtual void visit(array_init_t&){};
    virtual void visit(array_store_t&){};
    virtual void visit(array_load_t&){};
    virtual void visit(array_assign_t&){};

    void visit(basic_block_t& b);

    void visit(basic_block_rev_t& b);

    virtual ~statement_visitor() {}
};

class statement_t {
  protected:
    live_t m_live;
    stmt_code m_t_code;
    debug_info m_dbg_info;

    statement_t(stmt_code code = UNDEF, debug_info dbg_info = debug_info()) : m_t_code(code), m_dbg_info(dbg_info) {}

  public:
    virtual ~statement_t() {}

    bool is_bin_op() const { return (m_t_code == BIN_OP); }
    bool is_assign() const { return (m_t_code == ASSIGN); }
    bool is_assume() const { return (m_t_code == ASSUME); }
    bool is_select() const { return (m_t_code == SELECT); }
    bool is_assert() const { return (m_t_code == ASSERT); }
    bool is_int_cast() const { return (m_t_code == INT_CAST); }
    bool is_havoc() const { return m_t_code == HAVOC; }
    bool is_arr_init() const { return (m_t_code == ARR_INIT); }
    bool is_arr_read() const { return (m_t_code == ARR_LOAD); }
    bool is_arr_write() const { return (m_t_code == ARR_STORE); }
    bool is_arr_assign() const { return (m_t_code == ARR_ASSIGN); }
    const live_t& get_live() const { return m_live; }

    const debug_info& get_debug_info() const { return m_dbg_info; }

    virtual void accept(statement_visitor*) = 0;

    virtual void write(crab_os& o) const = 0;

    virtual statement_t* clone() const = 0;

    // for gdb
    void dump() const { write(errs()); }

    friend crab_os& operator<<(crab_os& o, const statement_t& s) {
        s.write(o);
        return o;
    }
};

/*
  Numerical statements
*/

class binary_op_t : public statement_t {
  public:
    binary_op_t(variable_t lhs, binary_operation_t op, linear_expression_t op1, linear_expression_t op2,
                debug_info dbg_info = debug_info())
        : statement_t(BIN_OP, dbg_info), m_lhs(lhs), m_op(op), m_op1(op1), m_op2(op2) {
        this->m_live.add_def(m_lhs);
        for (auto v : m_op1.variables()) {
            this->m_live.add_use(v);
        }
        for (auto v : m_op2.variables()) {
            this->m_live.add_use(v);
        }
    }

    variable_t lhs() const { return m_lhs; }

    binary_operation_t op() const { return m_op; }

    linear_expression_t left() const { return m_op1; }

    linear_expression_t right() const { return m_op2; }

    virtual void accept(statement_visitor* v) { v->visit(*this); }

    virtual statement_t* clone() const { return new binary_op_t(m_lhs, m_op, m_op1, m_op2, this->m_dbg_info); }

    virtual void write(crab_os& o) const { o << m_lhs << " = " << m_op1 << m_op << m_op2; }

  private:
    variable_t m_lhs;
    binary_operation_t m_op;
    linear_expression_t m_op1;
    linear_expression_t m_op2;
};

class assign_t : public statement_t {
  public:
    assign_t(variable_t lhs, linear_expression_t rhs) : statement_t(ASSIGN), m_lhs(lhs), m_rhs(rhs) {
        this->m_live.add_def(m_lhs);
        for (auto v : m_rhs.variables())
            this->m_live.add_use(v);
    }

    variable_t lhs() const { return m_lhs; }

    linear_expression_t rhs() const { return m_rhs; }

    virtual void accept(statement_visitor* v) { v->visit(*this); }

    virtual statement_t* clone() const { return new assign_t(m_lhs, m_rhs); }

    virtual void write(crab_os& o) const {
        o << m_lhs << " = " << m_rhs; // << " " << this->m_live;
    }

  private:
    variable_t m_lhs;
    linear_expression_t m_rhs;
};

class assume_t : public statement_t {
  public:
    assume_t(linear_constraint_t cst) : statement_t(ASSUME), m_cst(cst) {
        for (auto v : cst.variables())
            this->m_live.add_use(v);
    }

    linear_constraint_t constraint() const { return m_cst; }

    virtual void accept(statement_visitor* v) { v->visit(*this); }

    virtual statement_t* clone() const { return new assume_t(m_cst); }

    virtual void write(crab_os& o) const {
        o << "assume(" << m_cst << ")"; //  << " " << this->m_live;
    }

  private:
    linear_constraint_t m_cst;
};

class unreachable_t : public statement_t {
  public:
    unreachable_t() : statement_t(UNREACH) {}

    virtual void accept(statement_visitor* v) { v->visit(*this); }

    virtual statement_t* clone() const { return new unreachable_t(); }

    virtual void write(crab_os& o) const { o << "unreachable"; }
};

class havoc_t : public statement_t {
  public:
    havoc_t(variable_t lhs) : statement_t(HAVOC), m_lhs(lhs) { this->m_live.add_def(m_lhs); }

    variable_t variable() const { return m_lhs; }

    virtual void accept(statement_visitor* v) { v->visit(*this); }

    virtual statement_t* clone() const { return new havoc_t(m_lhs); }

    void write(crab_os& o) const { o << "havoc(" << m_lhs << ")"; }

  private:
    variable_t m_lhs;
};

// select x, c, e1, e2:
//    if c > 0 then x=e1 else x=e2
//
// Note that a select instruction is not strictly needed and can be
// simulated by splitting blocks. However, frontends like LLVM can
// generate many select instructions so we prefer to support
// natively to avoid a blow up in the size of the CFG.
class select_t : public statement_t {
  public:
    select_t(variable_t lhs, linear_constraint_t cond, linear_expression_t e1, linear_expression_t e2)
        : statement_t(SELECT), m_lhs(lhs), m_cond(cond), m_e1(e1), m_e2(e2) {
        this->m_live.add_def(m_lhs);
        for (auto v : m_cond.variables())
            this->m_live.add_use(v);
        for (auto v : m_e1.variables())
            this->m_live.add_use(v);
        for (auto v : m_e2.variables())
            this->m_live.add_use(v);
    }

    variable_t lhs() const { return m_lhs; }

    linear_constraint_t cond() const { return m_cond; }

    linear_expression_t left() const { return m_e1; }

    linear_expression_t right() const { return m_e2; }

    virtual void accept(statement_visitor* v) { v->visit(*this); }

    virtual statement_t* clone() const { return new select_t(m_lhs, m_cond, m_e1, m_e2); }

    virtual void write(crab_os& o) const {
        o << m_lhs << " = "
          << "ite(" << m_cond << "," << m_e1 << "," << m_e2 << ")";
    }

  private:
    variable_t m_lhs;
    linear_constraint_t m_cond;
    linear_expression_t m_e1;
    linear_expression_t m_e2;
};

class assert_t : public statement_t {
  public:
    assert_t(linear_constraint_t cst, debug_info dbg_info = debug_info()) : statement_t(ASSERT, dbg_info), m_cst(cst) {
        for (auto v : cst.variables())
            this->m_live.add_use(v);
    }

    linear_constraint_t constraint() const { return m_cst; }

    virtual void accept(statement_visitor* v) { v->visit(*this); }

    virtual statement_t* clone() const { return new assert_t(m_cst, this->m_dbg_info); }

    virtual void write(crab_os& o) const {
        o << "assert(" << m_cst << ")";
        if (this->m_dbg_info.has_debug()) {
            o << " // line=" << this->m_dbg_info.m_line << " column=" << this->m_dbg_info.m_col;
        }
    }

  private:
    linear_constraint_t m_cst;
};

class int_cast_t : public statement_t {
  public:
    using bitwidth_t = typename variable_t::bitwidth_t;

    int_cast_t(cast_operation_t op, variable_t src, variable_t dst, debug_info dbg_info = debug_info())
        : statement_t(INT_CAST, dbg_info), m_op(op), m_src(src), m_dst(dst) {
        this->m_live.add_use(m_src);
        this->m_live.add_def(m_dst);
    }

    cast_operation_t op() const { return m_op; }
    variable_t src() const { return m_src; }
    bitwidth_t src_width() const { return m_src.get_bitwidth(); }
    variable_t dst() const { return m_dst; }
    bitwidth_t dst_width() const { return m_dst.get_bitwidth(); }

    virtual void accept(statement_visitor* v) { v->visit(*this); }

    virtual statement_t* clone() const { return new int_cast_t(m_op, m_src, m_dst, this->m_dbg_info); }

    virtual void write(crab_os& o) const {
        // bitwidths are casted to int, otherwise operator<< may try
        // to print them as characters if bitwidth_t = uint8_t
        o << m_op << " " << m_src << ":" << (int)src_width() << " to " << m_dst << ":" << (int)dst_width();
    }

  private:
    cast_operation_t m_op;
    variable_t m_src;
    variable_t m_dst;
};

/*
  Array statements
*/

// XXX: the array statements array_init_t, array_store_t,
// and array_load_t take as one of their template parameters
// number_t which is the type for the array indexes. Although array
// indexes should be always integers we keep it as a template
// parameter in case an analysis over a type different from
// integers (e.g., reals) is done. Note that we don't allow mixing
// non-integers and integers so we cannot have analysis where all
// variables are non-integers except array indexes.
//
// Each of these statements requires an element size, that is, the
// number of bytes that are being accessed. If the front-end is
// LLVM, then the element size is always known at compilation
// time. However, with other front-ends (e.g., BPF programs) the
// element size is stored in a variable so that's why the type of
// the element size is not just a constant integer but it can also
// be a variable.

//! Initialize all array elements to some variable or number.
//  The semantics is similar to constant arrays in SMT.
class array_init_t : public statement_t {
  public:
    array_init_t(variable_t arr, linear_expression_t elem_size, linear_expression_t lb, linear_expression_t ub,
                 linear_expression_t val)
        : statement_t(ARR_INIT), m_arr(arr), m_elem_size(elem_size), m_lb(lb), m_ub(ub), m_val(val) {

        this->m_live.add_def(m_arr);
        for (auto v : m_elem_size.variables()) {
            this->m_live.add_use(v);
        }
        for (auto v : m_lb.variables()) {
            this->m_live.add_use(v);
        }
        for (auto v : m_ub.variables()) {
            this->m_live.add_use(v);
        }
        for (auto v : m_val.variables()) {
            this->m_live.add_use(v);
        }
    }

    variable_t array() const { return m_arr; }

    variable_type_t array_type() const { return m_arr.get_type(); }

    linear_expression_t elem_size() const { return m_elem_size; }

    linear_expression_t lb_index() const { return m_lb; }

    linear_expression_t ub_index() const { return m_ub; }

    linear_expression_t val() const { return m_val; }

    virtual void accept(statement_visitor* v) { v->visit(*this); }

    virtual statement_t* clone() const { return new array_init_t(m_arr, m_elem_size, m_lb, m_ub, m_val); }

    void write(crab_os& o) const { o << m_arr << "[" << m_lb << "..." << m_ub << "] := " << m_val; }

  private:
    // forall i \in [lb,ub) % elem_size :: arr[i] := val and
    // forall j < lb or j >= ub :: arr[j] is undefined.
    variable_t m_arr;
    linear_expression_t m_elem_size; //! size in bytes
    linear_expression_t m_lb;
    linear_expression_t m_ub;
    linear_expression_t m_val;
};

class array_store_t : public statement_t {
  public:
    // forall i \in [lb,ub) % elem_size :: arr[i] := val
    array_store_t(variable_t arr, linear_expression_t elem_size, linear_expression_t lb, linear_expression_t ub,
                  linear_expression_t value, bool is_singleton)
        : statement_t(ARR_STORE), m_arr(arr), m_elem_size(elem_size), m_lb(lb), m_ub(ub), m_value(value),
          m_is_singleton(is_singleton) {

        this->m_live.add_def(m_arr);
        for (auto v : m_elem_size.variables()) {
            this->m_live.add_use(v);
        }
        for (auto v : m_lb.variables()) {
            this->m_live.add_use(v);
        }
        for (auto v : m_ub.variables()) {
            this->m_live.add_use(v);
        }
        for (auto v : m_value.variables()) {
            this->m_live.add_use(v);
        }
    }

    variable_t array() const { return m_arr; }

    linear_expression_t lb_index() const { return m_lb; }

    linear_expression_t ub_index() const { return m_ub; }

    linear_expression_t value() const { return m_value; }

    variable_type_t array_type() const { return m_arr.get_type(); }

    linear_expression_t elem_size() const { return m_elem_size; }

    bool is_singleton() const { return m_is_singleton; }

    virtual void accept(statement_visitor* v) { v->visit(*this); }

    virtual statement_t* clone() const {
        return new array_store_t(m_arr, m_elem_size, m_lb, m_ub, m_value, m_is_singleton);
    }

    virtual void write(crab_os& o) const {
        if (m_lb.equal(m_ub)) {
            o << "array_store(" << m_arr << "," << m_lb << "," << m_value << ",sz=" << elem_size() << ")";
        } else {
            o << "array_store(" << m_arr << "," << m_lb << ".." << m_ub << "," << m_value << ",sz=" << elem_size()
              << ")";
        }
    }

  private:
    variable_t m_arr;
    linear_expression_t m_elem_size; //! size in bytes
    linear_expression_t m_lb;
    linear_expression_t m_ub;
    linear_expression_t m_value;
    bool m_is_singleton; // whether the store writes to a singleton
                         // cell (size one). If unknown set to false.
                         // Only makes sense if m_lb is equal to m_ub.
};

class array_load_t : public statement_t {
  public:
    array_load_t(variable_t lhs, variable_t arr, linear_expression_t elem_size, linear_expression_t index)
        : statement_t(ARR_LOAD), m_lhs(lhs), m_array(arr), m_elem_size(elem_size), m_index(index) {

        this->m_live.add_def(lhs);
        this->m_live.add_use(m_array);
        for (auto v : m_elem_size.variables()) {
            this->m_live.add_use(v);
        }
        for (auto v : m_index.variables()) {
            this->m_live.add_use(v);
        }
    }

    variable_t lhs() const { return m_lhs; }

    variable_t array() const { return m_array; }

    variable_type_t array_type() const { return m_array.get_type(); }

    linear_expression_t index() const { return m_index; }

    linear_expression_t elem_size() const { return m_elem_size; }

    virtual void accept(statement_visitor* v) { v->visit(*this); }

    virtual statement_t* clone() const { return new array_load_t(m_lhs, m_array, m_elem_size, m_index); }

    virtual void write(crab_os& o) const {
        o << m_lhs << " = "
          << "array_load(" << m_array << "," << m_index << ",sz=" << elem_size() << ")";
    }

  private:
    variable_t m_lhs;
    variable_t m_array;
    linear_expression_t m_elem_size; //! size in bytes
    linear_expression_t m_index;
};

class array_assign_t : public statement_t {
    //! a = b
  public:
    array_assign_t(variable_t lhs, variable_t rhs) : statement_t(ARR_ASSIGN), m_lhs(lhs), m_rhs(rhs) {
        this->m_live.add_def(lhs);
        this->m_live.add_use(rhs);
    }

    variable_t lhs() const { return m_lhs; }

    variable_t rhs() const { return m_rhs; }

    variable_type_t array_type() const { return m_lhs.get_type(); }

    virtual void accept(statement_visitor* v) { v->visit(*this); }

    virtual statement_t* clone() const { return new array_assign_t(m_lhs, m_rhs); }

    virtual void write(crab_os& o) const { o << m_lhs << " = " << m_rhs; }

  private:
    variable_t m_lhs;
    variable_t m_rhs;
};

class cfg_t;

class basic_block_t {
    basic_block_t(const basic_block_t&) = delete;

    friend class cfg_t;

  private:
    using bb_id_set_t = std::vector<basic_block_label_t>;
    using stmt_list_t = std::vector<statement_t*>;

  public:
    // -- iterators

    using succ_iterator = typename bb_id_set_t::iterator;
    using const_succ_iterator = typename bb_id_set_t::const_iterator;
    using pred_iterator = succ_iterator;
    using const_pred_iterator = const_succ_iterator;
    using iterator = boost::indirect_iterator<typename stmt_list_t::iterator>;
    using const_iterator = boost::indirect_iterator<typename stmt_list_t::const_iterator>;
    using reverse_iterator = boost::indirect_iterator<typename stmt_list_t::reverse_iterator>;
    using const_reverse_iterator = boost::indirect_iterator<typename stmt_list_t::const_reverse_iterator>;
    using live_domain_t = discrete_domain<variable_t>;

    // -- statements

  private:
    basic_block_label_t m_bb_id;
    stmt_list_t m_ts;
    bb_id_set_t m_prev, m_next;
    // set of used/def variables
    live_domain_t m_live{live_domain_t::bottom()};

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

    basic_block_t(basic_block_label_t bb_id)
        : m_bb_id(bb_id) {}

    static basic_block_t* create(basic_block_label_t bb_id) {
        return new basic_block_t(bb_id);
    }

    void update_uses_and_defs(const statement_t* s) {
        auto ls = s->get_live();
        for (auto& v : boost::make_iterator_range(ls.uses_begin(), ls.uses_end())) {
            m_live += v;
        }
        for (auto& v : boost::make_iterator_range(ls.defs_begin(), ls.defs_end())) {
            m_live += v;
        }
    }

    void insert(statement_t* stmt) {
        m_ts.push_back(stmt);
        update_uses_and_defs(stmt);
    }

  public:
    // The basic block owns the statements
    ~basic_block_t() {
        for (unsigned i = 0, e = m_ts.size(); i < e; ++i) {
            delete m_ts[i];
        }
    }

    basic_block_t* clone() const {
        // The basic block labels (i.e., identifiers) are not cloned.

        basic_block_t* b = new basic_block_t(label());
        for (auto& s : boost::make_iterator_range(begin(), end())) {
            b->m_ts.push_back(s.clone());
        }

        for (auto id : boost::make_iterator_range(prev_blocks())) {
            b->m_prev.push_back(id);
        }
        for (auto id : boost::make_iterator_range(next_blocks())) {
            b->m_next.push_back(id);
        }

        b->m_live = m_live;
        return b;
    }

    basic_block_label_t label() const { return m_bb_id; }

    std::string name() const { return get_label_str(m_bb_id); }

    iterator begin() { return boost::make_indirect_iterator(m_ts.begin()); }
    iterator end() { return boost::make_indirect_iterator(m_ts.end()); }
    const_iterator begin() const { return boost::make_indirect_iterator(m_ts.begin()); }
    const_iterator end() const { return boost::make_indirect_iterator(m_ts.end()); }

    reverse_iterator rbegin() { return boost::make_indirect_iterator(m_ts.rbegin()); }
    reverse_iterator rend() { return boost::make_indirect_iterator(m_ts.rend()); }
    const_reverse_iterator rbegin() const { return boost::make_indirect_iterator(m_ts.rbegin()); }
    const_reverse_iterator rend() const { return boost::make_indirect_iterator(m_ts.rend()); }

    size_t size() const { return std::distance(begin(), end()); }

    live_domain_t& live() { return m_live; }

    const live_domain_t& live() const { return m_live; }

    // Collect the set of uses and definitions of the basic block
    void update_uses_and_defs() {
        for (const statement_t* s : m_ts) {
            update_uses_and_defs(s);
        }
    }

    void accept(statement_visitor* v) { v->visit(*this); }

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

    // insert all statements of other at the front
    void copy_front(const basic_block_t& other) {
        std::vector<statement_t*> cloned_ts;
        cloned_ts.reserve(other.size());
        std::transform(other.m_ts.begin(), other.m_ts.end(), std::back_inserter(cloned_ts),
                       [](const statement_t* s) { return s->clone(); });

        m_ts.insert(m_ts.begin(), cloned_ts.begin(), cloned_ts.end());

        m_live = m_live | other.m_live;
    }

    // insert all statements of other at the back
    void copy_back(const basic_block_t& other) {
        std::vector<statement_t*> cloned_ts;
        cloned_ts.reserve(other.size());
        std::transform(other.m_ts.begin(), other.m_ts.end(), std::back_inserter(cloned_ts),
                       [](const statement_t* s) { return s->clone(); });

        m_ts.insert(m_ts.end(), cloned_ts.begin(), cloned_ts.end());

        m_live = m_live | other.m_live;
    }

    // Remove s (and free) from this
    void remove(const statement_t* s, bool must_update_uses_and_defs = true) {
        // remove statement using the remove-erase idiom
        m_ts.erase(std::remove_if(m_ts.begin(), m_ts.end(), [s](const statement_t* o) { return (o == s); }),
                   m_ts.end());

        if (must_update_uses_and_defs) {
            update_uses_and_defs();
        }
        delete s;
    }

    // Pre: old is a statement at position i in this
    //      new is not part of any basic block.
    // Post: old is deleted (and freed) and new is at position i in
    //       the basic block.
    void replace(statement_t* old_s, statement_t* new_s) {
        std::replace(m_ts.begin(), m_ts.end(), old_s, new_s);
        delete old_s;
    }

    void write(crab_os& o) const {
        o << get_label_str(m_bb_id) << ":\n";
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
                o << get_label_str(*it);
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

    void add(variable_t lhs, variable_t op1, variable_t op2) { insert(new binary_op_t(lhs, BINOP_ADD, op1, op2)); }

    void add(variable_t lhs, variable_t op1, number_t op2) { insert(new binary_op_t(lhs, BINOP_ADD, op1, op2)); }

    void sub(variable_t lhs, variable_t op1, variable_t op2) { insert(new binary_op_t(lhs, BINOP_SUB, op1, op2)); }

    void sub(variable_t lhs, variable_t op1, number_t op2) { insert(new binary_op_t(lhs, BINOP_SUB, op1, op2)); }

    void mul(variable_t lhs, variable_t op1, variable_t op2) { insert(new binary_op_t(lhs, BINOP_MUL, op1, op2)); }

    void mul(variable_t lhs, variable_t op1, number_t op2) { insert(new binary_op_t(lhs, BINOP_MUL, op1, op2)); }

    // signed division
    void div(variable_t lhs, variable_t op1, variable_t op2) { insert(new binary_op_t(lhs, BINOP_SDIV, op1, op2)); }

    void div(variable_t lhs, variable_t op1, number_t op2) { insert(new binary_op_t(lhs, BINOP_SDIV, op1, op2)); }

    // unsigned division
    void udiv(variable_t lhs, variable_t op1, variable_t op2) { insert(new binary_op_t(lhs, BINOP_UDIV, op1, op2)); }

    void udiv(variable_t lhs, variable_t op1, number_t op2) { insert(new binary_op_t(lhs, BINOP_UDIV, op1, op2)); }

    // signed rem
    void rem(variable_t lhs, variable_t op1, variable_t op2) { insert(new binary_op_t(lhs, BINOP_SREM, op1, op2)); }

    void rem(variable_t lhs, variable_t op1, number_t op2) { insert(new binary_op_t(lhs, BINOP_SREM, op1, op2)); }

    // unsigned rem
    void urem(variable_t lhs, variable_t op1, variable_t op2) { insert(new binary_op_t(lhs, BINOP_UREM, op1, op2)); }

    void urem(variable_t lhs, variable_t op1, number_t op2) { insert(new binary_op_t(lhs, BINOP_UREM, op1, op2)); }

    void bitwise_and(variable_t lhs, variable_t op1, variable_t op2) {
        insert(new binary_op_t(lhs, BINOP_AND, op1, op2));
    }

    void bitwise_and(variable_t lhs, variable_t op1, number_t op2) {
        insert(new binary_op_t(lhs, BINOP_AND, op1, op2));
    }

    void bitwise_or(variable_t lhs, variable_t op1, variable_t op2) {
        insert(new binary_op_t(lhs, BINOP_OR, op1, op2));
    }

    void bitwise_or(variable_t lhs, variable_t op1, number_t op2) { insert(new binary_op_t(lhs, BINOP_OR, op1, op2)); }

    void bitwise_xor(variable_t lhs, variable_t op1, variable_t op2) {
        insert(new binary_op_t(lhs, BINOP_XOR, op1, op2));
    }

    void bitwise_xor(variable_t lhs, variable_t op1, number_t op2) {
        insert(new binary_op_t(lhs, BINOP_XOR, op1, op2));
    }

    void shl(variable_t lhs, variable_t op1, variable_t op2) { insert(new binary_op_t(lhs, BINOP_SHL, op1, op2)); }

    void shl(variable_t lhs, variable_t op1, number_t op2) { insert(new binary_op_t(lhs, BINOP_SHL, op1, op2)); }

    void lshr(variable_t lhs, variable_t op1, variable_t op2) { insert(new binary_op_t(lhs, BINOP_LSHR, op1, op2)); }

    void lshr(variable_t lhs, variable_t op1, number_t op2) { insert(new binary_op_t(lhs, BINOP_LSHR, op1, op2)); }

    void ashr(variable_t lhs, variable_t op1, variable_t op2) { insert(new binary_op_t(lhs, BINOP_ASHR, op1, op2)); }

    void ashr(variable_t lhs, variable_t op1, number_t op2) { insert(new binary_op_t(lhs, BINOP_ASHR, op1, op2)); }

    void assign(variable_t lhs, linear_expression_t rhs) { insert(new assign_t(lhs, rhs)); }

    void assume(linear_constraint_t cst) { insert(new assume_t(cst)); }

    void havoc(variable_t lhs) { insert(new havoc_t(lhs)); }

    void unreachable() { insert(new unreachable_t()); }

    void select(variable_t lhs, variable_t v, linear_expression_t e1, linear_expression_t e2) {
        linear_constraint_t cond(exp_gte(v, 1));
        insert(new select_t(lhs, cond, e1, e2));
    }

    void select(variable_t lhs, linear_constraint_t cond, linear_expression_t e1, linear_expression_t e2) {
        insert(new select_t(lhs, cond, e1, e2));
    }

    void assertion(linear_constraint_t cst, debug_info di = debug_info()) { insert(new assert_t(cst, di)); }

    void truncate(variable_t src, variable_t dst) { insert(new int_cast_t(CAST_TRUNC, src, dst)); }

    void sext(variable_t src, variable_t dst) { insert(new int_cast_t(CAST_SEXT, src, dst)); }

    void zext(variable_t src, variable_t dst) { insert(new int_cast_t(CAST_ZEXT, src, dst)); }

    void array_init(variable_t a, linear_expression_t lb_idx, linear_expression_t ub_idx, linear_expression_t v,
                    linear_expression_t elem_size) {
        insert(new array_init_t(a, elem_size, lb_idx, ub_idx, v));
    }

    void array_store(variable_t arr, linear_expression_t idx, linear_expression_t v, linear_expression_t elem_size,
                     bool is_singleton = false) {
        insert(new array_store_t(arr, elem_size, idx, idx, v, is_singleton));
    }

    void array_store_range(variable_t arr, linear_expression_t lb_idx, linear_expression_t ub_idx,
                           linear_expression_t v, linear_expression_t elem_size) {
        insert(new array_store_t(arr, elem_size, lb_idx, ub_idx, v, false));
    }

    void array_load(variable_t lhs, variable_t arr, linear_expression_t idx, linear_expression_t elem_size) {
        insert(new array_load_t(lhs, arr, elem_size, idx));
    }

    void array_assign(variable_t lhs, variable_t rhs) {
        insert(new array_assign_t(lhs, rhs));
    }

    friend crab_os& operator<<(crab_os& o, const basic_block_t& b) {
        b.write(o);
        return o;
    }
};

// Viewing basic_block_t with all statements reversed. Useful for
// backward analysis.
class basic_block_rev_t {
  public:
    using succ_iterator = typename basic_block_t::succ_iterator;
    using const_succ_iterator = typename basic_block_t::const_succ_iterator;
    using pred_iterator = succ_iterator;
    using const_pred_iterator = const_succ_iterator;

    using iterator = typename basic_block_t::reverse_iterator;
    using const_iterator = typename basic_block_t::const_reverse_iterator;
    using live_domain_t = discrete_domain<variable_t>;

  private:
    basic_block_t& _bb;

  public:
    basic_block_rev_t(basic_block_t& bb) : _bb(bb) {}

    basic_block_label_t label() const { return _bb.label(); }

    std::string name() const { return _bb.name(); }

    iterator begin() { return _bb.rbegin(); }

    iterator end() { return _bb.rend(); }

    const_iterator begin() const { return _bb.rbegin(); }

    const_iterator end() const { return _bb.rend(); }

    std::size_t size() const { return std::distance(begin(), end()); }

    void accept(statement_visitor* v) { v->visit(*this); }

    live_domain_t& live() { return _bb.live(); }

    live_domain_t live() const { return _bb.live(); }

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

// forward declarations
class cfg_rev_t;
class cfg_ref_t;

class cfg_t {
    cfg_t(const cfg_t&) = delete;

  public:
    using node_t = basic_block_label_t; // for Bgl graphs

    using succ_iterator = typename basic_block_t::succ_iterator;
    using pred_iterator = typename basic_block_t::pred_iterator;
    using const_succ_iterator = typename basic_block_t::const_succ_iterator;
    using const_pred_iterator = typename basic_block_t::const_pred_iterator;

    using succ_range = boost::iterator_range<succ_iterator>;
    using pred_range = boost::iterator_range<pred_iterator>;
    using const_succ_range = boost::iterator_range<const_succ_iterator>;
    using const_pred_range = boost::iterator_range<const_pred_iterator>;

  private:
    using basic_block_map_t = boost::unordered_map<basic_block_label_t, basic_block_t*>;
    using binding_t = typename basic_block_map_t::value_type;
    using live_domain_t = typename basic_block_t::live_domain_t;

    struct get_ref : public std::unary_function<binding_t, basic_block_t> {
        get_ref() {}
        basic_block_t& operator()(const binding_t& p) const { return *(p.second); }
    };

    struct get_label : public std::unary_function<binding_t, basic_block_label_t> {
        get_label() {}
        basic_block_label_t operator()(const binding_t& p) const { return p.second->label(); }
    };

  public:
    using iterator = boost::transform_iterator<get_ref, typename basic_block_map_t::iterator>;
    using const_iterator = boost::transform_iterator<get_ref, typename basic_block_map_t::const_iterator>;
    using label_iterator = boost::transform_iterator<get_label, typename basic_block_map_t::iterator>;
    using const_label_iterator = boost::transform_iterator<get_label, typename basic_block_map_t::const_iterator>;

    using var_iterator = typename std::vector<varname_t>::iterator;
    using const_var_iterator = typename std::vector<varname_t>::const_iterator;

  private:
    basic_block_label_t m_entry;
    std::optional<basic_block_label_t> m_exit;
    basic_block_map_t m_blocks;

    using visited_t = boost::unordered_set<basic_block_label_t>;
    template <typename T>
    void dfs_rec(basic_block_label_t curId, visited_t& visited, T f) const {
        if (!visited.insert(curId).second)
            return;

        const basic_block_t& cur = get_node(curId);
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
    cfg_t(basic_block_label_t entry)
        : m_entry(entry), m_exit(std::nullopt) {
        m_blocks.insert(binding_t(m_entry, basic_block_t::create(m_entry)));
    }

    cfg_t(basic_block_label_t entry, basic_block_label_t exit)
        : m_entry(entry), m_exit(exit) {
        m_blocks.insert(binding_t(m_entry, basic_block_t::create(m_entry)));
    }

    // The cfg_t owns the basic blocks
    ~cfg_t() {
        for (auto& kv : m_blocks) {
            delete kv.second;
        }
    }

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
        const basic_block_t& b = get_node(bb_id);
        return boost::make_iterator_range(b.next_blocks());
    }

    const_pred_range prev_nodes(basic_block_label_t bb_id) const {
        const basic_block_t& b = get_node(bb_id);
        return boost::make_iterator_range(b.prev_blocks());
    }

    succ_range next_nodes(basic_block_label_t bb_id) {
        basic_block_t& b = get_node(bb_id);
        return boost::make_iterator_range(b.next_blocks());
    }

    pred_range prev_nodes(basic_block_label_t bb_id) {
        basic_block_t& b = get_node(bb_id);
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

    basic_block_t& insert(basic_block_label_t bb_id) {
        auto it = m_blocks.find(bb_id);
        if (it != m_blocks.end())
            return *(it->second);

        basic_block_t* block = basic_block_t::create(bb_id);
        m_blocks.insert(binding_t(bb_id, block));
        return *block;
    }

    void remove(basic_block_label_t bb_id) {
        if (bb_id == m_entry) {
            CRAB_ERROR("Cannot remove entry block");
        }

        if (m_exit && *m_exit == bb_id) {
            CRAB_ERROR("Cannot remove exit block");
        }

        std::vector<std::pair<basic_block_t*, basic_block_t*>> dead_edges;
        basic_block_t* bb = &(get_node(bb_id));

        for (auto id : boost::make_iterator_range(bb->prev_blocks())) {
            if (bb_id != id) {
                basic_block_t& p = get_node(id);
                dead_edges.push_back({&p, bb});
            }
        }

        for (auto id : boost::make_iterator_range(bb->next_blocks())) {
            if (bb_id != id) {
                basic_block_t& s = get_node(id);
                dead_edges.push_back({bb, &s});
            }
        }

        for (auto p : dead_edges) {
            (*p.first) -= (*p.second);
        }

        m_blocks.erase(bb_id);
        delete bb;
    }

    // // Return all variables (either used or defined) in the cfg_t.
    // //
    // // This operation is linear on the size of the cfg_t to still keep
    // // a valid set in case a block is removed.
    // std::vector<varname_t> get_vars() const {
    //     live_domain_t ls = live_domain_t::bottom();
    //     for (auto const &b : boost::make_iterator_range(begin(), end()))
    //         ls = ls | b.live();
    //     // std::vector<varname_t> vars(ls.size());
    //     // vars.insert(vars.end(), ls.begin(), ls.end());
    //     std::vector<varname_t> vars;
    //     for (auto v : ls)
    //         vars.push_back(v);
    //     return vars;
    // }

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

    friend crab_os& operator<<(crab_os& o, const cfg_t& cfg_t) {
        cfg_t.write(o);
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

        basic_block_t& cur = get_node(curId);

        if (has_one_child(curId) && has_one_parent(curId)) {
            basic_block_t& parent = get_parent(curId);
            basic_block_t& child = get_child(curId);

            // Merge with its parent if it's its only child.
            if (has_one_child(parent.label())) {
                // move all statements from cur to parent
                parent.copy_back(cur);
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

    // remove unreachable blocks
    void remove_unreachable_blocks() {
        visited_t alive, dead;
        mark_alive_blocks(entry(), *this, alive);

        for (auto const& bb : *this) {
            if (!(alive.count(bb.label()) > 0)) {
                dead.insert(bb.label());
            }
        }

        for (auto bb_id : dead) {
            remove(bb_id);
        }
    }

    // remove blocks that cannot reach the exit block
    void remove_useless_blocks();
};

// A lightweight object that wraps a reference to a CFG into a
// copyable, assignable object.
class cfg_ref_t {
    using CFG = cfg_t;

  public:
    // CFG's typedefs
    using node_t = typename CFG::node_t;

    using succ_iterator = typename CFG::succ_iterator;
    using pred_iterator = typename CFG::pred_iterator;
    using const_succ_iterator = typename CFG::const_succ_iterator;
    using const_pred_iterator = typename CFG::const_pred_iterator;
    using succ_range = typename CFG::succ_range;
    using pred_range = typename CFG::pred_range;
    using const_succ_range = typename CFG::const_succ_range;
    using const_pred_range = typename CFG::const_pred_range;
    using iterator = typename CFG::iterator;
    using const_iterator = typename CFG::const_iterator;
    using label_iterator = typename CFG::label_iterator;
    using const_label_iterator = typename CFG::const_label_iterator;
    using var_iterator = typename CFG::var_iterator;
    using const_var_iterator = typename CFG::const_var_iterator;

  private:
    std::optional<std::reference_wrapper<CFG>> _ref;

  public:
    // --- hook needed by cg::CallGraph<CFG>::CgNode
    cfg_ref_t() {}

    cfg_ref_t(CFG& cfg_t) : _ref(std::reference_wrapper<CFG>(cfg_t)) {}

    const CFG& get() const {
        assert(_ref);
        return *_ref;
    }

    CFG& get() {
        assert(_ref);
        return *_ref;
    }

    basic_block_label_t entry() const {
        assert(_ref);
        return (*_ref).get().entry();
    }

    const_succ_range next_nodes(basic_block_label_t bb) const {
        assert(_ref);
        return (*_ref).get().next_nodes(bb);
    }

    const_pred_range prev_nodes(basic_block_label_t bb) const {
        assert(_ref);
        return (*_ref).get().prev_nodes(bb);
    }

    succ_range next_nodes(basic_block_label_t bb) {
        assert(_ref);
        return (*_ref).get().next_nodes(bb);
    }

    pred_range prev_nodes(basic_block_label_t bb) {
        assert(_ref);
        return (*_ref).get().prev_nodes(bb);
    }

    basic_block_t& get_node(basic_block_label_t bb) {
        assert(_ref);
        return (*_ref).get().get_node(bb);
    }

    const basic_block_t& get_node(basic_block_label_t bb) const {
        assert(_ref);
        return (*_ref).get().get_node(bb);
    }

    size_t size() const {
        assert(_ref);
        return (*_ref).get().size();
    }

    iterator begin() {
        assert(_ref);
        return (*_ref).get().begin();
    }

    iterator end() {
        assert(_ref);
        return (*_ref).get().end();
    }

    const_iterator begin() const {
        assert(_ref);
        return (*_ref).get().begin();
    }

    const_iterator end() const {
        assert(_ref);
        return (*_ref).get().end();
    }

    label_iterator label_begin() {
        assert(_ref);
        return (*_ref).get().label_begin();
    }

    label_iterator label_end() {
        assert(_ref);
        return (*_ref).get().label_end();
    }

    const_label_iterator label_begin() const {
        assert(_ref);
        return (*_ref).get().label_begin();
    }

    const_label_iterator label_end() const {
        assert(_ref);
        return (*_ref).get().label_end();
    }

    bool has_exit() const {
        assert(_ref);
        return (*_ref).get().has_exit();
    }

    basic_block_label_t exit() const {
        assert(_ref);
        return (*_ref).get().exit();
    }

    friend crab_os& operator<<(crab_os& o, const cfg_ref_t& cfg_t) {
        o << cfg_t.get();
        return o;
    }

    // for gdb
    void dump() const {
        assert(_ref);
        (*_ref).get().dump();
    }

    void simplify() {
        assert(_ref);
        (*_ref).get().simplify();
    }

    // #include <boost/fusion/functional/invocation/invoke.hpp>
    // template< class... ArgTypes >
    // typename std::result_of<CFG&(ArgTypes&&...)>::type
    // operator() ( ArgTypes&&... args ) const {
    //   return boost::fusion::invoke(get(), std::forward<ArgTypes>(args)...);
    // }
};

// Viewing a CFG with all edges and block statements
// reversed. Useful for backward analysis.
class cfg_rev_t {
  public:
    using node_t = basic_block_label_t; // for Bgl graphs

    using pred_range = typename cfg_ref_t::succ_range;
    using succ_range = typename cfg_ref_t::pred_range;
    using const_pred_range = typename cfg_ref_t::const_succ_range;
    using const_succ_range = typename cfg_ref_t::const_pred_range;

    // For BGL
    using succ_iterator = typename basic_block_t::succ_iterator;
    using pred_iterator = typename basic_block_t::pred_iterator;
    using const_succ_iterator = typename basic_block_t::const_succ_iterator;
    using const_pred_iterator = typename basic_block_t::const_pred_iterator;

  private:
    struct getRev : public std::unary_function<basic_block_t, basic_block_rev_t> {
        const boost::unordered_map<basic_block_label_t, basic_block_rev_t>& _rev_bbs;

        getRev(const boost::unordered_map<basic_block_label_t, basic_block_rev_t>& rev_bbs) : _rev_bbs(rev_bbs) {}

        const basic_block_rev_t& operator()(basic_block_t& bb) const {
            auto it = _rev_bbs.find(bb.label());
            if (it != _rev_bbs.end())
                return it->second;
            CRAB_ERROR("Basic block ", bb.label(), " not found in the CFG: ", __LINE__);
        }
    };

    using visited_t = boost::unordered_set<basic_block_label_t>;

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
    using iterator = boost::transform_iterator<getRev, cfg_ref_t::iterator>;
    using const_iterator = boost::transform_iterator<getRev, cfg_ref_t::const_iterator>;
    using label_iterator = cfg_ref_t::label_iterator;
    using const_label_iterator = cfg_ref_t::const_label_iterator;
    using var_iterator = cfg_ref_t::var_iterator;
    using const_var_iterator = cfg_ref_t::const_var_iterator;

  private:
    cfg_ref_t _cfg;
    boost::unordered_map<basic_block_label_t, basic_block_rev_t> _rev_bbs;

  public:
    // --- hook needed by cg::CallGraph<cfg_ref_t>::CgNode
    cfg_rev_t() {}

    cfg_rev_t(cfg_ref_t cfg_t) : _cfg(cfg_t) {
        // Create basic_block_rev_t from basic_block_t objects
        // Note that basic_block_rev_t is also a view of basic_block_t so it
        // doesn't modify basic_block_t objects.
        for (auto& bb : cfg_t) {
            basic_block_rev_t rev(bb);
            _rev_bbs.insert(std::make_pair(bb.label(), rev));
        }
    }

    cfg_rev_t(const cfg_rev_t& o) : _cfg(o._cfg), _rev_bbs(o._rev_bbs) {}

    cfg_rev_t(cfg_rev_t&& o) : _cfg(std::move(o._cfg)), _rev_bbs(std::move(o._rev_bbs)) {}

    cfg_rev_t& operator=(const cfg_rev_t& o) {
        if (this != &o) {
            _cfg = o._cfg;
            _rev_bbs = o._rev_bbs;
        }
        return *this;
    }

    cfg_rev_t& operator=(cfg_rev_t&& o) {
        _cfg = std::move(o._cfg);
        _rev_bbs = std::move(o._rev_bbs);
        return *this;
    }

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
