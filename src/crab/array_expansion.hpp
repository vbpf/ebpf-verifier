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

#include "boost/range/algorithm/set_algorithm.hpp"
#include <algorithm>
#include <optional>
#include <set>
#include <vector>

namespace crab {
namespace domains {

// wrapper for using index_t as patricia_tree keys
class offset_t final {
    index_t _val{};

  public:
    offset_t() = default;
    explicit offset_t(index_t v) : _val(v) {}

    index_t index() const { return _val; }

    bool operator<(const offset_t& o) const { return _val < o._val; }

    bool operator==(const offset_t& o) const { return _val == o._val; }

    bool operator!=(const offset_t& o) const { return !(*this == o); }

    void write(std::ostream& o) const { o << _val; }

    friend std::ostream& operator<<(std::ostream& o, const offset_t& v) {
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

class cell_t final {
  private:
    friend class offset_map_t;

    offset_t _offset{};
    unsigned _size{};

    // Only offset_map_t can create cells
    cell_t() = default;

    cell_t(offset_t offset, unsigned size) : _offset(offset), _size(size) {}

    static interval_t to_interval(const offset_t o, unsigned size) {
        return {static_cast<int>(o.index()),
                static_cast<int>(o.index()) + static_cast<int>(size - 1)}; }

    interval_t to_interval() const { return to_interval(_offset, _size); }

  public:
    bool is_null() const { return _offset.index() == 0 && _size == 0; }

    offset_t get_offset() const { return _offset; }

    variable_t get_scalar(data_kind_t kind) const {
        return variable_t::cell_var(kind, _offset.index(), _size);
    }

    // ignore the scalar variable
    bool operator==(const cell_t& o) const { return to_interval() == o.to_interval(); }

    // ignore the scalar variable
    bool operator<(const cell_t& o) const {
        if (_offset == o._offset)
            return _size < o._size;
        return _offset < o._offset;
    }

    // Return true if [o, o+size) definitely overlaps with the cell,
    // where o is a constant expression.
    bool overlap(const offset_t& o, unsigned size) const {
        interval_t x = to_interval();
        interval_t y = to_interval(o, size);
        bool res = (!(x & y).is_bottom());
        CRAB_LOG("array-expansion-overlap",
                 std::cout << "**Checking if " << x << " overlaps with " << y << "=" << res << "\n";);
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
                 std::cout << "**Checking if " << *this << " overlaps with symbolic "
                        << "[" << tmp_symb_lb << "," << tmp_symb_ub << "]"
                        << " with abstract state=" << tmp << "\n";);

        AbsDomain tmp1(dom);
        tmp1 += linear_constraint_t(symb_lb - lb, linear_constraint_t::INEQUALITY); //(lb >= symb_lb);
        tmp1 += linear_constraint_t(lb - symb_lb, linear_constraint_t::INEQUALITY); //(lb <= symb_ub);
        if (!tmp1.is_bottom()) {
            CRAB_LOG("array-expansion-overlap", std::cout << "\tyes.\n";);
            return true;
        }

        AbsDomain tmp2(dom);
        tmp2 += linear_constraint_t(symb_ub - ub, linear_constraint_t::INEQUALITY); // (ub >= symb_lb);
        tmp2 += linear_constraint_t(ub - symb_ub, linear_constraint_t::INEQUALITY); // (ub <= symb_ub);
        if (!tmp2.is_bottom()) {
            CRAB_LOG("array-expansion-overlap", std::cout << "\tyes.\n";);
            return true;
        }

        CRAB_LOG("array-expansion-overlap", std::cout << "\tno.\n";);
        return false;
    }

    void write(std::ostream& o) const {
        o << "cell(" << to_interval() << ")";
    }

    friend std::ostream& operator<<(std::ostream& o, const cell_t& c) {
        c.write(o);
        return o;
    }
};

// forward declarations
template <typename AbsDomain>
class array_expansion_domain;

// Map offsets to cells
class offset_map_t final {
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

    class domain_po : public partial_order_t {
        bool leq(cell_set_t x, cell_set_t y) {
            {
                cell_set_t z;
                boost::set_difference(x, y, std::inserter(z, z.end()));
                return z.empty();
            }
        }
        // default value is bottom (i.e., empty map)
        bool default_is_top() { return false; }
    }; // class domain_po

    offset_map_t(patricia_tree_t m) : _map(m) {}

    void remove_cell(const cell_t& c);

    void insert_cell(const cell_t& c);

    std::optional<cell_t> get_cell(offset_t o, unsigned size) const;

    cell_t mk_cell(offset_t o, unsigned size);

  public:
    offset_map_t() = default;

    bool empty() const { return _map.empty(); }

    std::size_t size() const { return _map.size(); }

    // leq operator
    bool operator<=(const offset_map_t& o) const {
        domain_po po;
        return _map.leq(o._map, po);
    }

    void operator-=(const cell_t& c) { remove_cell(c); }

    void operator-=(const std::vector<cell_t>& cells) {
        for (unsigned i = 0, e = cells.size(); i < e; ++i) {
            this->operator-=(cells[i]);
        }
    }

    std::vector<cell_t> get_all_cells() const;

    // Return in out all cells that might overlap with (o, size).
    std::vector<cell_t> get_overlap_cells(offset_t o, unsigned size);

    template <typename AbsDomain>
    std::vector<cell_t> get_overlap_cells_symbolic_offset(const AbsDomain& dom, const linear_expression_t& symb_lb,
                                           const linear_expression_t& symb_ub) const {
        std::vector<cell_t> out;
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
        return out;
    }

    void write(std::ostream& o) const;

    friend std::ostream& operator<<(std::ostream& o, const offset_map_t& m) {
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

// We use a global array map
using array_map_t = boost::unordered_map<data_kind_t, offset_map_t>;
extern array_map_t global_array_map;
void clear_global_state();

template <typename NumAbsDomain>
class array_expansion_domain final : public writeable {
  private:
    using array_expansion_domain_t = array_expansion_domain<NumAbsDomain>;

  public:
    using variable_vector_t = std::vector<variable_t>;
    using content_domain_t = NumAbsDomain;

  private:

    // scalar domain
    NumAbsDomain _inv;

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

  private:
    offset_map_t& lookup_array_map(data_kind_t kind) {
        return global_array_map[kind];
    }

    array_expansion_domain(NumAbsDomain inv) : _inv(inv) {}

    void kill_cells(data_kind_t kind, const std::vector<cell_t>& cells, offset_map_t& offset_map, NumAbsDomain& dom) {
        if (!cells.empty()) {
            // Forget the scalars from the numerical domain
            for (unsigned i = 0, e = cells.size(); i < e; ++i) {
                dom -= cells[i].get_scalar(kind);
            }
            // Remove the cells. If needed again they they will be re-created.
            offset_map -= cells;
        }
    }

    interval_t to_interval(linear_expression_t expr, NumAbsDomain inv) {
        interval_t r(expr.constant());
        for (typename linear_expression_t::iterator it = expr.begin(); it != expr.end(); ++it) {
            interval_t c(it->first);
            r += c * inv[it->second];
        }
        return r;
    }

  public:

    interval_t to_interval(linear_expression_t expr) { return to_interval(expr, _inv); }

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
    }

    void normalize() { CRAB_WARN("array expansion normalize not implemented"); }

    void operator+=(linear_constraint_t cst) { _inv += cst; }

    void operator-=(variable_t var) {
        _inv -= var;
    }

    void assign(variable_t x, linear_expression_t e) { _inv.assign(x, e); }

    void apply(arith_binop_t op, variable_t x, variable_t y, number_t z) { _inv.apply(op, x, y, z); }

    void apply(arith_binop_t op, variable_t x, variable_t y, variable_t z) { _inv.apply(op, x, y, z); }

    void apply(bitwise_binop_t op, variable_t x, variable_t y, variable_t z) { _inv.apply(op, x, y, z); }

    void apply(bitwise_binop_t op, variable_t x, variable_t y, number_t k) { _inv.apply(op, x, y, k); }

    template <typename NumOrVar>
    void apply(binop_t op, variable_t x, variable_t y, NumOrVar z) {
        std::visit([&](auto top) { apply(top, x, y, z); }, op);
    }
    // array_operators_api

    void array_load(variable_t lhs, data_kind_t kind, linear_expression_t i, int width) {

        if (is_bottom())
            return;

        interval_t ii = to_interval(i);
        if (std::optional<number_t> n = ii.singleton()) {
            offset_map_t& offset_map = lookup_array_map(kind);
            offset_t o((long)*n);
            unsigned size = (long)width;
            std::vector<cell_t> cells = offset_map.get_overlap_cells(o, size);
            if (cells.empty()) {
                cell_t c = offset_map.mk_cell(o, size);
                // Here it's ok to do assignment (instead of expand)
                // because c is not a summarized variable. Otherwise, it
                // would be unsound.
                _inv.assign(lhs, c.get_scalar(kind));
                return;
            } else {
                CRAB_WARN("Ignored read from cell ", kind, "[", o, "...", o.index() + size - 1, "]",
                            " because it overlaps with ", cells.size(), " cells");
                /*
                    TODO: we can apply here "Value Recomposition" 'a la'
                    Mine'06 to construct values of some type from a sequence
                    of bytes. It can be endian-independent but it would more
                    precise if we choose between little- and big-endian.
                */
            }
        } else {
            // TODO: we can be more precise here
            CRAB_WARN("array expansion: ignored array load because of non-constant array index ", i);
        }

        _inv -= lhs;
    }

    std::optional<std::pair<offset_t, unsigned>> kill_and_find_var(data_kind_t kind, linear_expression_t i, linear_expression_t elem_size) {
        if (is_bottom())
            return {};

        std::optional<std::pair<offset_t, unsigned>> res;

        offset_map_t& offset_map = lookup_array_map(kind);
        interval_t ii = to_interval(i);
        std::vector<cell_t> cells;
        if (std::optional<number_t> n = ii.singleton()) {
            interval_t i_elem_size = to_interval(elem_size);
            std::optional<number_t> n_bytes = i_elem_size.singleton();
            if (n_bytes) {
                unsigned size = (long)(*n_bytes);
                // -- Constant index: kill overlapping cells
                offset_t o((long)*n);
                cells = offset_map.get_overlap_cells(o, size);
                res = std::make_pair(o, size);
            }
        }
        if (!res) {
            // -- Non-constant index: kill overlapping cells
            cells = offset_map.get_overlap_cells_symbolic_offset(_inv,
                linear_expression_t(i),
                linear_expression_t(i + elem_size)
            );
        }
        kill_cells(kind, cells, offset_map, _inv);

        return res;
    }

    void array_store(data_kind_t kind, linear_expression_t idx, linear_expression_t elem_size, linear_expression_t val) {
        auto maybe_cell = kill_and_find_var(kind, idx, elem_size);
        if (maybe_cell) {
            // perform strong update
            //std::cout << "(" << maybe_cell->first.index() << ", " << maybe_cell->second << ")\n";
            auto [offset, size] = *maybe_cell;
            variable_t v = lookup_array_map(kind).mk_cell(offset, size).get_scalar(kind);
            _inv.assign(v, val);
        }
    }

    void array_havoc(data_kind_t kind, linear_expression_t idx, linear_expression_t elem_size) {
        kill_and_find_var(kind, idx, elem_size);
    }
    // Perform array stores over an array segment
    void array_store_range(data_kind_t kind, linear_expression_t _idx,
                           linear_expression_t _width, linear_expression_t val) {

        // TODO: this should be an user parameter.
        const number_t max_num_elems = 512;

        if (is_bottom())
            return;

        interval_t idx_i = to_interval(_idx);
        auto idx_n = idx_i.singleton();
        if (!idx_n) {
            CRAB_WARN("array expansion store range ignored because ", "lower bound is not constant");
            return;
        }

        interval_t width_i = to_interval(_width);
        auto width = width_i.singleton();
        if (!width) {
            CRAB_WARN("array expansion store range ignored because ", "upper bound is not constant");
            return;
        }

        if (*idx_n + *width > max_num_elems) {
            CRAB_WARN("array expansion store range ignored because ",
                      "the number of elements is larger than default limit of ", max_num_elems);
            return;
        }

        offset_map_t& offset_map = lookup_array_map(kind);
        kill_cells(kind, offset_map.get_overlap_cells(offset_t((long)*idx_n), (unsigned)(int)*width), offset_map, _inv);
        auto idx = *idx_n;
        for (number_t i = 0; i < *width; i = i + 1) {
            // perform strong update
            variable_t v = offset_map.mk_cell(offset_t((long)idx), 1).get_scalar(kind);
            _inv.assign(v, val);
            idx = idx + 1;
        }
    }

    NumAbsDomain get_content_domain() const { return _inv; }

    NumAbsDomain& get_content_domain() { return _inv; }

    void write(std::ostream& o) { o << _inv; }

    static std::string getDomainName() {
        std::string name("ArrayExpansion(" + NumAbsDomain::getDomainName() + ")");
        return name;
    }

    void rename(const variable_vector_t& from, const variable_vector_t& to) {
        _inv.rename(from, to);
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
