/*******************************************************************************
 * Array expansion domain
 *
 * For a given array, map sequences of consecutive bytes to cells
 * consisting of a triple <offset, size, var> where:
 *
 * - offset is an unsigned number
 * - size  is an unsigned number
 * - var is a scalar variable that represents the content of
 *   a[offset,...,offset+size-1]
 *
 * The domain is general enough to represent any possible sequence of
 * consecutive bytes including sequences of bytes starting at the same
 * offsets but different sizes, overlapping sequences starting at
 * different offsets, etc. However, there are some cases that have
 * been implemented an imprecise manner:
 *
 * (1) array store/load with a non-constant index are conservatively ignored.
 * (2) array load from a cell that overlaps with other cells return top.
 ******************************************************************************/

#pragma once

#include "crab/abstract_domain.hpp"
#include "crab/abstract_domain_specialized_traits.hpp"
#include "crab/debug.hpp"
#include "crab/stats.hpp"
#include "crab/types.hpp"

#include "crab/interval.hpp"
#include "crab/patricia_trees.hpp"
#include "crab/separate_domains.hpp"

#include "boost/range/algorithm/set_algorithm.hpp"
#include <algorithm>
#include <optional>
#include <set>
#include <vector>

namespace crab {
namespace domains {

// wrapper for using index_t as patricia_tree keys
class offset_t {
    index_t _val{};

  public:
    offset_t() = default;
    explicit offset_t(index_t v) : _val(v) {}

    index_t index() const { return _val; }

    bool operator<(const offset_t& o) const { return _val < o._val; }

    bool operator==(const offset_t& o) const { return _val == o._val; }

    bool operator!=(const offset_t& o) const { return !(*this == o); }

    void write(crab_os& o) const { o << _val; }

    friend crab_os& operator<<(crab_os& o, const offset_t& v) {
        v.write(o);
        return o;
    }
};

/*
   Conceptually, a cell is tuple of an array, offset, size, and
   scalar variable such that:

       _scalar = array[_offset, _offset+1,...,_offset+_size-1]

   For simplicity, we don't carry the array inside the cell class.
   Only, offset_map objects can create cells. They will consider the
   array when generating the scalar variable.
*/

class offset_map_t;

class cell_t {
  private:
    friend class offset_map_t;

    offset_t _offset{};
    unsigned _size{};
    std::optional<variable_t> _scalar{};

    // Only offset_map_t can create cells
    cell_t() = default;
    cell_t(offset_t offset, variable_t scalar) : _offset(offset), _size(scalar.get_bitwidth()), _scalar(scalar) {}

    cell_t(offset_t offset, unsigned size) : _offset(offset), _size(size) {}

    static interval_t to_interval(const offset_t o, unsigned size) {
        interval_t i(o.index(), o.index() + size - 1);
        return i;
    }

    interval_t to_interval() const { return to_interval(get_offset(), get_size()); }

  public:
    bool is_null() const { return (_offset.index() == 0 && _size == 0); }

    offset_t get_offset() const { return _offset; }

    size_t get_size() const { return _size; }

    bool has_scalar() const { return (bool)_scalar; }

    variable_t get_scalar() const {
        if (!has_scalar()) {
            CRAB_ERROR("cannot get undefined scalar variable");
        }
        return *_scalar;
    }

    // inclusion test
    bool operator<=(const cell_t& o) const {
        interval_t x = to_interval();
        interval_t y = o.to_interval();
        return x <= y;
    }

    // ignore the scalar variable
    bool operator==(const cell_t& o) const { return (get_offset() == o.get_offset() && get_size() == o.get_size()); }

    // ignore the scalar variable
    bool operator<(const cell_t& o) const {
        if (get_offset() < o.get_offset()) {
            return true;
        } else if (get_offset() == o.get_offset()) {
            return get_size() < o.get_size();
        } else {
            return false;
        }
    }

    // Return true if [o, o+size) definitely overlaps with the cell,
    // where o is a constant expression.
    bool overlap(const offset_t& o, unsigned size) const {
        interval_t x = to_interval();
        interval_t y = to_interval(o, size);
        bool res = (!(x & y).is_bottom());
        CRAB_LOG("array-expansion-overlap",
                 outs() << "**Checking if " << x << " overlaps with " << y << "=" << res << "\n";);
        return res;
    }

    // Return true if [symb_lb, symb_ub] may overlap with the cell,
    // where symb_lb and symb_ub are not constant expressions.
    template <typename AbsDomain>
    bool symbolic_overlap(const linear_expression_t& symb_lb, const linear_expression_t& symb_ub,
                          const AbsDomain& dom) const {

        interval_t x = to_interval();
        assert(x.lb().is_finite());
        assert(x.ub().is_finite());
        linear_expression_t lb(*(x.lb().number()));
        linear_expression_t ub(*(x.ub().number()));

        CRAB_LOG("array-expansion-overlap", AbsDomain tmp(dom); linear_expression_t tmp_symb_lb(symb_lb);
                 linear_expression_t tmp_symb_ub(symb_ub);
                 outs() << "**Checking if " << *this << " overlaps with symbolic "
                        << "[" << tmp_symb_lb << "," << tmp_symb_ub << "]"
                        << " with abstract state=" << tmp << "\n";);

        AbsDomain tmp1(dom);
        tmp1 += linear_constraint_t(symb_lb - lb, linear_constraint_t::INEQUALITY); //(lb >= symb_lb);
        tmp1 += linear_constraint_t(lb - symb_lb, linear_constraint_t::INEQUALITY); //(lb <= symb_ub);
        if (!tmp1.is_bottom()) {
            CRAB_LOG("array-expansion-overlap", outs() << "\tyes.\n";);
            return true;
        }

        AbsDomain tmp2(dom);
        tmp2 += linear_constraint_t(symb_ub - ub, linear_constraint_t::INEQUALITY); // (ub >= symb_lb);
        tmp2 += linear_constraint_t(ub - symb_ub, linear_constraint_t::INEQUALITY); // (ub <= symb_ub);
        if (!tmp2.is_bottom()) {
            CRAB_LOG("array-expansion-overlap", outs() << "\tyes.\n";);
            return true;
        }

        CRAB_LOG("array-expansion-overlap", outs() << "\tno.\n";);
        return false;
    }

    void write(crab_os& o) const {
        o << to_interval() << " -> ";
        if (has_scalar()) {
            o << get_scalar();
        } else {
            o << "_";
        }
    }

    friend crab_os& operator<<(crab_os& o, const cell_t& c) {
        c.write(o);
        return o;
    }
};

namespace cell_set_impl {
template <typename Set>
inline Set set_intersection(Set& s1, Set& s2) {
    Set s3;
    boost::set_intersection(s1, s2, std::inserter(s3, s3.end()));
    return s3;
}

template <typename Set>
inline Set set_union(Set& s1, Set& s2) {
    Set s3;
    boost::set_union(s1, s2, std::inserter(s3, s3.end()));
    return s3;
}

template <typename Set>
inline bool set_inclusion(Set& s1, Set& s2) {
    Set s3;
    boost::set_difference(s1, s2, std::inserter(s3, s3.end()));
    return s3.empty();
}
} // namespace cell_set_impl

// forward declarations
template <typename AbsDomain>
class array_expansion_domain;

// Map offsets to cells
class offset_map_t {
  private:
    template <typename AbsDomain>
    friend class array_expansion_domain;

    using cell_set_t = std::set<cell_t>;

    /*
      The keys in the patricia tree are processing in big-endian
      order. This means that the keys are sorted. Sortedeness is
      very important to perform efficiently operations such as
      checking for overlap cells. Since keys are treated as bit
      patterns, negative offsets can be used but they are treated
      as large unsigned numbers.
    */
    using patricia_tree_t = patricia_tree<offset_t, cell_set_t>;
    using partial_order_t = typename patricia_tree_t::partial_order_t;

    patricia_tree_t _map;

    // for algorithm::lower_bound and algorithm::upper_bound
    struct compare_binding_t {
        bool operator()(const typename patricia_tree_t::binding_t& kv, const offset_t& o) const { return kv.first < o; }
        bool operator()(const offset_t& o, const typename patricia_tree_t::binding_t& kv) const { return o < kv.first; }
        bool operator()(const typename patricia_tree_t::binding_t& kv1,
                        const typename patricia_tree_t::binding_t& kv2) const {
            return kv1.first < kv2.first;
        }
    };

    // patricia_tree_t apply_operation(binary_op_t &o, patricia_tree_t t1, patricia_tree_t t2) {
    //     t1.merge_with(t2, o);
    //     return t1;
    // }

    class join_op : public binary_op_t {
        // apply is called when two bindings (one each from a
        // different map) have the same key(i.e., offset).
        std::pair<bool, std::optional<cell_set_t>> apply(cell_set_t x, cell_set_t y) {
            return {false, cell_set_impl::set_union(x, y)};
        }
        // if one map does not have a key in the other map we add it.
        bool default_is_absorbing() { return false; }
    };

    class meet_op : public binary_op_t {
        std::pair<bool, std::optional<cell_set_t>> apply(cell_set_t x, cell_set_t y) {
            return {false, cell_set_impl::set_intersection(x, y)};
        }
        // if one map does not have a key in the other map we ignore
        // it.
        bool default_is_absorbing() { return true; }
    };

    class domain_po : public partial_order_t {
        bool leq(cell_set_t x, cell_set_t y) { return cell_set_impl::set_inclusion(x, y); }
        // default value is bottom (i.e., empty map)
        bool default_is_top() { return false; }
    }; // class domain_po

    offset_map_t(patricia_tree_t m) : _map(m) {}

    void remove_cell(const cell_t& c);

    void insert_cell(const cell_t& c, bool sanity_check = true);

    cell_t get_cell(offset_t o, unsigned size) const;

    static std::string mk_scalar_name(variable_t a, offset_t o, unsigned size);

    static variable_type_t get_array_element_type(variable_type_t array_type) { return INT_TYPE; }

    // global state to map the same triple of array, offset and size
    // to same index
    static std::map<std::pair<index_t, std::pair<offset_t, unsigned>>, index_t> _index_map;

    index_t get_index(variable_t a, offset_t o, unsigned size) {
        auto it = _index_map.find({a.index(), {o, size}});
        if (it != _index_map.end()) {
            return it->second;
        } else {
            index_t res = _index_map.size();
            _index_map.insert({{a.index(), {o, size}}, res});
            return res;
        }
    }

    cell_t mk_cell(variable_t array, offset_t o, unsigned size);

  public:
    offset_map_t() = default;

    bool empty() const { return _map.empty(); }

    std::size_t size() const { return _map.size(); }

    // leq operator
    bool operator<=(const offset_map_t& o) const {
        domain_po po;
        return _map.leq(o._map, po);
    }

    // // set union: if two cells with same offset do not agree on
    // // size then they are ignored.
    // offset_map_t operator|(const offset_map_t &o) {
    //     join_op op;
    //     return offset_map_t(apply_operation(op, _map, o._map));
    // }

    // // set intersection: if two cells with same offset do not agree
    // // on size then they are ignored.
    // offset_map_t operator&(const offset_map_t &o) {
    //     meet_op op;
    //     return offset_map_t(apply_operation(op, _map, o._map));
    // }

    void operator-=(const cell_t& c) { remove_cell(c); }

    void operator-=(const std::vector<cell_t>& cells) {
        for (unsigned i = 0, e = cells.size(); i < e; ++i) {
            this->operator-=(cells[i]);
        }
    }

    std::vector<cell_t> get_all_cells() const;

    // Return in out all cells that might overlap with (o, size).
    void get_overlap_cells(offset_t o, unsigned size, std::vector<cell_t>& out);

    template <typename AbsDomain>
    void get_overlap_cells_symbolic_offset(const AbsDomain& dom, const linear_expression_t& symb_lb,
                                           const linear_expression_t& symb_ub, std::vector<cell_t>& out) const {

        for (auto it = _map.begin(), et = _map.end(); it != et; ++it) {
            const cell_set_t& o_cells = it->second;
            // All cells in o_cells have the same offset. They only differ
            // in the size. If the largest cell overlaps with [offset,
            // offset + size) then the rest of cells are considered to
            // overlap. This is an over-approximation because [offset,
            // offset+size) can overlap with the largest cell but it
            // doesn't necessarily overlap with smaller cells. For
            // efficiency, we assume it overlaps with all.
            cell_t largest_cell;
            for (auto& c : o_cells) {
                if (largest_cell.is_null()) {
                    largest_cell = c;
                } else {
                    assert(c.get_offset() == largest_cell.get_offset());
                    if (largest_cell < c) {
                        largest_cell = c;
                    }
                }
            }
            if (!largest_cell.is_null()) {
                if (largest_cell.symbolic_overlap(symb_lb, symb_ub, dom)) {
                    for (auto& c : o_cells) {
                        out.push_back(c);
                    }
                }
            }
        }
    }

    void write(crab_os& o) const;

    friend crab_os& operator<<(crab_os& o, const offset_map_t& m) {
        m.write(o);
        return o;
    }

    /* Operations needed if used as value in a separate_domain */
    bool operator==(const offset_map_t& o) const { return *this <= o && o <= *this; }
    bool is_top() const { return empty(); }
    bool is_bottom() const { return false; }
    /*
       We don't distinguish between bottom and top.
       This is fine because separate_domain only calls bottom if
       operator[] is called over a bottom state. Thus, we will make
       sure that we don't call operator[] in that case.
    */
    static offset_map_t bottom() { return offset_map_t(); }
    static offset_map_t top() { return offset_map_t(); }
};

// /* for debugging */
// namespace array_expansion_domain_impl{
//   template<typename AbsDomain>
//   inline void print_size(const AbsDomain& dom) {}

//   template<typename N, typename V>
//   inline void print_size(const domains::SplitDBM<N,V>& dom) {
//     outs() << "(" << dom.size().first << "," << dom.size().second << ")";
//   }
// }

template <typename NumAbsDomain>
class array_expansion_domain final : public writeable {
  private:
    using array_expansion_domain_t = array_expansion_domain<NumAbsDomain>;

  public:
    using variable_vector_t = std::vector<variable_t>;
    using content_domain_t = NumAbsDomain;

  private:
    using array_map_t = boost::unordered_map<variable_t, offset_map_t>;

    // scalar domain
    NumAbsDomain _inv;

    // We use a global array map
    static array_map_t& get_array_map() {
        static array_map_t* array_map = new array_map_t();
        return *array_map;
    }

  public:
    static array_expansion_domain_t top() {
        array_expansion_domain_t abs;
        abs.set_to_top();
        return abs;
    }

    static array_expansion_domain_t bottom() {
        array_expansion_domain_t abs;
        abs.set_to_bottom();
        return abs;
    }

    /**
        Ugly this needs to be fixed: needed if multiple analyses are
        run so we can clear the array map from one run to another.
    **/
    static void clear_global_state() {
        array_map_t& map = get_array_map();
        if (!map.empty()) {
            if (crab::CrabSanityCheckFlag) {
                CRAB_WARN("array_expansion static variable map is being cleared");
            }
            map.clear();
        }
    }

  private:
    void remove_array_map(const variable_t& v) {
        /// We keep the array map as global so we don't remove any entry.
        // array_map_t& map = get_array_map();
        // map.erase(v);
    }

    offset_map_t& lookup_array_map(const variable_t& v) {
        array_map_t& map = get_array_map();
        return map[v];
    }

    array_expansion_domain(NumAbsDomain inv) : _inv(inv) {}

    interval_t to_interval(linear_expression_t expr, NumAbsDomain inv) {
        interval_t r(expr.constant());
        for (typename linear_expression_t::iterator it = expr.begin(); it != expr.end(); ++it) {
            interval_t c(it->first);
            r += c * inv[it->second];
        }
        return r;
    }

    interval_t to_interval(linear_expression_t expr) { return to_interval(expr, _inv); }

    void kill_cells(const std::vector<cell_t>& cells, offset_map_t& offset_map, NumAbsDomain& dom) {
        if (!cells.empty()) {
            // Forget the scalars from the numerical domain
            for (unsigned i = 0, e = cells.size(); i < e; ++i) {
                const cell_t& c = cells[i];
                if (c.has_scalar()) {
                    dom -= c.get_scalar();
                } else {
                    CRAB_ERROR("array expansion: cell without scalar variable in array store");
                }
            }
            // Remove the cells. If needed again they they will be re-created.
            offset_map -= cells;
        }
    }

  public:
    array_expansion_domain() : _inv(NumAbsDomain::top()) {}

    void set_to_top() {
        array_expansion_domain abs(NumAbsDomain::top());
        std::swap(*this, abs);
    }

    void set_to_bottom() {
        array_expansion_domain abs(NumAbsDomain::bottom());
        std::swap(*this, abs);
    }

    array_expansion_domain(const array_expansion_domain_t& other) : _inv(other._inv) {}

    array_expansion_domain(const array_expansion_domain_t&& other) : _inv(std::move(other._inv)) {}

    array_expansion_domain_t& operator=(const array_expansion_domain_t& other) {
        if (this != &other) {
            _inv = other._inv;
        }
        return *this;
    }

    array_expansion_domain_t& operator=(const array_expansion_domain_t&& other) {
        if (this != &other) {
            _inv = std::move(other._inv);
        }
        return *this;
    }

    bool is_bottom() { return (_inv.is_bottom()); }

    bool is_top() { return (_inv.is_top()); }

    bool operator<=(array_expansion_domain_t other) { return (_inv <= other._inv); }

    bool operator==(array_expansion_domain_t other) { return (_inv <= other._inv && other._inv <= _inv); }

    void operator|=(array_expansion_domain_t other) { _inv |= other._inv; }

    array_expansion_domain_t operator|(array_expansion_domain_t other) {
        return array_expansion_domain_t(_inv | other._inv);
    }

    array_expansion_domain_t operator&(array_expansion_domain_t other) {

        return array_expansion_domain_t(_inv & other._inv);
    }

    array_expansion_domain_t widen(array_expansion_domain_t other) {

        return array_expansion_domain_t(_inv.widen(other._inv));
    }

    array_expansion_domain_t widening_thresholds(array_expansion_domain_t other, const iterators::thresholds_t& ts) {
        return array_expansion_domain_t(_inv.widening_thresholds(other._inv, ts));
    }

    array_expansion_domain_t narrow(array_expansion_domain_t other) {
        return array_expansion_domain_t(_inv.narrow(other._inv));
    }

    void forget(const variable_vector_t& variables) {

        if (is_bottom() || is_top()) {
            return;
        }

        _inv.forget(variables);

        for (variable_t v : variables) {
            if (v.is_array_type()) {
                remove_array_map(v);
            }
        }
    }

    void normalize() { CRAB_WARN("array expansion normalize not implemented"); }

    void operator+=(linear_constraint_t cst) { _inv += cst; }

    void operator-=(variable_t var) {

        if (var.is_array_type()) {
            remove_array_map(var);
        } else {
            _inv -= var;
        }
    }

    void assign(variable_t x, linear_expression_t e) { _inv.assign(x, e); }

    void apply(operation_t op, variable_t x, variable_t y, number_t z) { _inv.apply(op, x, y, z); }

    void apply(operation_t op, variable_t x, variable_t y, variable_t z) { _inv.apply(op, x, y, z); }

    void apply(int_conv_operation_t op, variable_t dst, variable_t src) { _inv.apply(op, dst, src); }

    void apply(bitwise_operation_t op, variable_t x, variable_t y, variable_t z) { _inv.apply(op, x, y, z); }

    void apply(bitwise_operation_t op, variable_t x, variable_t y, number_t k) { _inv.apply(op, x, y, k); }

    // array_operators_api

    // array_init returns a fresh array where all elements between
    // lb_idx and ub_idx are initialized to val. Thus, the first thing
    // we need to do is to kill existing cells.
    void array_init(variable_t a, linear_expression_t elem_size, linear_expression_t lb_idx, linear_expression_t ub_idx,
                    linear_expression_t val) {

        if (is_bottom())
            return;

        offset_map_t& offset_map = lookup_array_map(a);
        std::vector<cell_t> old_cells = offset_map.get_all_cells();
        if (!old_cells.empty()) {
            kill_cells(old_cells, offset_map, _inv);
        }

        array_store_range(a, elem_size, lb_idx, ub_idx, val);
    }

    void array_load(variable_t lhs, variable_t a, linear_expression_t elem_size, linear_expression_t i) {

        if (is_bottom())
            return;

        interval_t ii = to_interval(i);
        if (std::optional<number_t> n = ii.singleton()) {
            offset_map_t& offset_map = lookup_array_map(a);
            offset_t o((long)*n);
            interval_t i_elem_size = to_interval(elem_size);
            if (std::optional<number_t> n_bytes = i_elem_size.singleton()) {
                unsigned size = (long)*n_bytes;
                std::vector<cell_t> cells;
                offset_map.get_overlap_cells(o, size, cells);
                if (!cells.empty()) {
                    CRAB_WARN("Ignored read from cell ", a, "[", o, "...", o.index() + size - 1, "]",
                              " because it overlaps with ", cells.size(), " cells");
                    /*
                       TODO: we can apply here "Value Recomposition" 'a la'
                       Mine'06 to construct values of some type from a sequence
                       of bytes. It can be endian-independent but it would more
                       precise if we choose between little- and big-endian.
                    */
                } else {
                    cell_t c = offset_map.mk_cell(a, o, size);
                    assert(c.has_scalar());
                    // Here it's ok to do assignment (instead of expand)
                    // because c is not a summarized variable. Otherwise, it
                    // would be unsound.
                    _inv.assign(lhs, c.get_scalar());
                    goto array_load_end;
                }
            } else {
                CRAB_ERROR("array expansion domain expects constant array element sizes");
            }
        } else {
            // TODO: we can be more precise here
            CRAB_WARN("array expansion: ignored array load because of non-constant array index ", i);
        }

        _inv -= lhs;

    array_load_end:
        CRAB_LOG("array-expansion", linear_expression_t ub = i + elem_size - 1;
                 outs() << lhs << ":=" << a << "[" << i << "..." << ub << "]  -- " << *this << "\n";);
    }

    void array_store(variable_t a, linear_expression_t elem_size, linear_expression_t i, linear_expression_t val,
                     bool /*is_singleton*/) {

        if (is_bottom())
            return;

        interval_t i_elem_size = to_interval(elem_size);
        std::optional<number_t> n_bytes = i_elem_size.singleton();
        if (!n_bytes) {
            CRAB_ERROR("array expansion domain expects constant array element sizes");
        }

        unsigned size = (long)(*n_bytes);
        offset_map_t& offset_map = lookup_array_map(a);
        interval_t ii = to_interval(i);
        if (std::optional<number_t> n = ii.singleton()) {
            // -- Constant index: kill overlapping cells + perform strong update
            std::vector<cell_t> cells;
            offset_t o((long)*n);
            offset_map.get_overlap_cells(o, size, cells);
            if (cells.size() > 0) {
                CRAB_LOG("array-expansion", CRAB_WARN("Killed ", cells.size(), " overlapping cells with ", "[", o,
                                                      "...", o.index() + size - 1, "]", " before writing."));

                kill_cells(cells, offset_map, _inv);
            }
            // Perform scalar update
            // -- create a new cell it there is no one already
            cell_t c = offset_map.mk_cell(a, o, size);
            // -- strong update
            _inv.assign(c.get_scalar(), val);
        } else {
            // -- Non-constant index: kill overlapping cells
            CRAB_WARN("array expansion ignored array write with non-constant index ", i);
            linear_expression_t symb_lb(i);
            linear_expression_t symb_ub(i + number_t(size - 1));
            std::vector<cell_t> cells;
            offset_map.get_overlap_cells_symbolic_offset(_inv, symb_lb, symb_ub, cells);
            CRAB_LOG("array-expansion", outs() << "Killed cells: {"; for (unsigned j = 0; j < cells.size();) {
                outs() << cells[j];
                ++j;
                if (j < cells.size()) {
                    outs() << ",";
                }
            } outs() << "}\n";);
            kill_cells(cells, offset_map, _inv);
        }

        CRAB_LOG("array-expansion", linear_expression_t ub = i + elem_size - 1;
                 outs() << a << "[" << i << "..." << ub << "]:=" << val << " -- " << *this << "\n";);
    }

    // Perform array stores over an array segment
    void array_store_range(variable_t a, linear_expression_t elem_size, linear_expression_t lb_idx,
                           linear_expression_t ub_idx, linear_expression_t val) {

        // TODO: this should be an user parameter.
        const number_t max_num_elems = 512;

        if (is_bottom())
            return;

        interval_t n_i = to_interval(elem_size);
        auto n = n_i.singleton();
        if (!n) {
            CRAB_ERROR("array expansion domain expects constant array element sizes");
        }

        interval_t lb_i = to_interval(lb_idx);
        auto lb = lb_i.singleton();
        if (!lb) {
            CRAB_WARN("array expansion store range ignored because ", "lower bound is not constant");
            return;
        }

        interval_t ub_i = to_interval(ub_idx);
        auto ub = ub_i.singleton();
        if (!ub) {
            CRAB_WARN("array expansion store range ignored because ", "upper bound is not constant");
            return;
        }

        if ((*ub - *lb) % *n != 0) {
            CRAB_WARN("array expansion store range ignored because ", "the number of elements must be divisible by ",
                      *n);
            return;
        }

        if (*ub - *lb > max_num_elems) {
            CRAB_WARN("array expansion store range ignored because ",
                      "the number of elements is larger than default limit of ", max_num_elems);
            return;
        }

        for (number_t i = *lb, e = *ub; i < e;) {
            array_store(a, elem_size, i, val, false);
            i = i + *n;
        }
    }

    void array_assign(variable_t lhs, variable_t rhs) {
        //_array_map[lhs] = _array_map[rhs];
        CRAB_ERROR("array_assign in array_expansion domain not implemented");
    }

    NumAbsDomain get_content_domain() const { return _inv; }

    NumAbsDomain& get_content_domain() { return _inv; }

    void write(crab_os& o) { o << _inv; }

    static std::string getDomainName() {
        std::string name("ArrayExpansion(" + NumAbsDomain::getDomainName() + ")");
        return name;
    }

    void rename(const variable_vector_t& from, const variable_vector_t& to) {
        _inv.rename(from, to);
        for (auto& v : from) {
            if (v.is_array_type()) {
                CRAB_WARN("TODO: rename array variable");
            }
        }
    }

}; // end array_expansion_domain

template <typename BaseDom>
class checker_domain_traits<array_expansion_domain<BaseDom>> {
  public:
    using this_type = array_expansion_domain<BaseDom>;

    static bool entail(this_type& lhs, const linear_constraint_t& rhs) {
        BaseDom& lhs_dom = lhs.get_content_domain();
        return checker_domain_traits<BaseDom>::entail(lhs_dom, rhs);
    }

    static bool intersect(this_type& inv, const linear_constraint_t& cst) {
        BaseDom& dom = inv.get_content_domain();
        return checker_domain_traits<BaseDom>::intersect(dom, cst);
    }
};

} // namespace domains
} // namespace crab
