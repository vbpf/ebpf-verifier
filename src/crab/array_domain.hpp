// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
/*******************************************************************************
 * Array expansion domain
 *
 * For a given array, map sequences of consecutive bytes to cells
 * consisting of a triple <offset, size, var> where:
 *
 * - offset is an unsigned number
 * - size is an unsigned number
 * - var is a scalar variable that represents the content of
 *   a[offset, ..., offset + size - 1]
 *
 * The domain is general enough to represent any possible sequence of
 * consecutive bytes including sequences of bytes starting at the same
 * offsets but different sizes, overlapping sequences starting at
 * different offsets, etc. However, there are some cases that have
 * been implemented in an imprecise manner:
 *
 * (1) array store/load with a non-constant index are conservatively ignored.
 * (2) array load from a cell that overlaps with other cells return top.
 ******************************************************************************/

#pragma once

#include <algorithm>
#include <bitset>
#include <functional>
#include <optional>
#include <set>
#include <unordered_map>
#include <utility>
#include <vector>

#include "boost/range/algorithm/set_algorithm.hpp"

#include "crab/variable.hpp"
#include "crab_utils/debug.hpp"
#include "crab_utils/stats.hpp"

#include "crab/interval.hpp"
#include "crab/split_dbm.hpp"
#include "crab_utils/patricia_trees.hpp"

#include "asm_ostream.hpp"
#include "config.hpp"
#include "dsl_syntax.hpp"
#include "helpers.hpp"
#include "spec_type_descriptors.hpp"

#include "crab/bitset_domain.hpp"

namespace crab::domains {

// Numerical abstract domain.
using NumAbsDomain = SplitDBM;

using offset_t = index_t;

/*
   Conceptually, a cell is tuple of an array, offset, size, and
   scalar variable such that:

       _scalar = array[_offset, _offset + 1, ..., _offset + _size - 1]

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
        return {static_cast<int>(o), static_cast<int>(o) + static_cast<int>(size - 1)};
    }

    [[nodiscard]] interval_t to_interval() const { return to_interval(_offset, _size); }

  public:
    [[nodiscard]] bool is_null() const { return _offset == 0 && _size == 0; }

    [[nodiscard]] offset_t get_offset() const { return _offset; }

    [[nodiscard]] variable_t get_scalar(data_kind_t kind) const { return variable_t::cell_var(kind, _offset, _size); }

    // ignore the scalar variable
    bool operator==(const cell_t& o) const { return to_interval() == o.to_interval(); }

    // ignore the scalar variable
    bool operator<(const cell_t& o) const {
        if (_offset == o._offset)
            return _size < o._size;
        return _offset < o._offset;
    }

    // Return true if [o, o + size) definitely overlaps with the cell,
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
    [[nodiscard]]
    bool symbolic_overlap(const linear_expression_t& symb_lb,
                          const linear_expression_t& symb_ub,
                          const NumAbsDomain& dom) const;

    friend std::ostream& operator<<(std::ostream& o, const cell_t& c) { return o << "cell(" << c.to_interval() << ")"; }
};

// forward declarations
class array_domain_t;

// Map offsets to cells
class offset_map_t final {
  private:
    friend class array_domain_t;

    using cell_set_t = std::set<cell_t>;

    /*
      The keys in the patricia tree are processing in big-endian
      order. This means that the keys are sorted. Sortedness is
      very important to efficiently perform operations such as
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
        bool leq(cell_set_t x, cell_set_t y) override {
            {
                cell_set_t z;
                boost::set_difference(x, y, std::inserter(z, z.end()));
                return z.empty();
            }
        }
        // default value is bottom (i.e., empty map)
        bool default_is_top() override { return false; }
    }; // class domain_po

    explicit offset_map_t(const patricia_tree_t& m) : _map(m) {}

    void remove_cell(const cell_t& c);

    void insert_cell(const cell_t& c);

    [[nodiscard]] std::optional<cell_t> get_cell(offset_t o, unsigned size) const;

    cell_t mk_cell(offset_t o, unsigned size);

  public:
    offset_map_t() = default;

    [[nodiscard]] bool empty() const { return _map.empty(); }

    [[nodiscard]] std::size_t size() const { return _map.size(); }

    // leq operator
    bool operator<=(const offset_map_t& o) const {
        domain_po po;
        return _map.leq(o._map, po);
    }

    void operator-=(const cell_t& c) { remove_cell(c); }

    void operator-=(const std::vector<cell_t>& cells) {
        for (auto c : cells) {
            this->operator-=(c);
        }
    }

    // Return in out all cells that might overlap with (o, size).
    std::vector<cell_t> get_overlap_cells(offset_t o, unsigned size);

    [[nodiscard]] std::vector<cell_t> get_overlap_cells_symbolic_offset(const NumAbsDomain& dom,
                                                                        const linear_expression_t& symb_lb,
                                                                        const linear_expression_t& symb_ub) const;

    friend std::ostream& operator<<(std::ostream& o, const offset_map_t& m);

    /* Operations needed if used as value in a separate_domain */
    bool operator==(const offset_map_t& o) const { return *this <= o && o <= *this; }
    [[nodiscard]] bool is_top() const { return empty(); }
    [[nodiscard]] bool is_bottom() const { return false; }
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
using array_map_t = std::unordered_map<data_kind_t, offset_map_t>;
extern array_map_t global_array_map;
void clear_global_state();

class array_domain_t final {
    bitset_domain_t num_bytes;

  private:
    static offset_map_t& lookup_array_map(data_kind_t kind) { return global_array_map[kind]; }

    static std::optional<std::pair<offset_t, unsigned>>
    kill_and_find_var(NumAbsDomain& inv, data_kind_t kind, const linear_expression_t& i, const linear_expression_t& elem_size);

  public:
    array_domain_t() = default;

    array_domain_t(const bitset_domain_t& num_bytes) : num_bytes(num_bytes) { }

    void set_to_top() {
        num_bytes.set_to_top();
    }

    void set_to_bottom() { num_bytes.set_to_bottom(); }

    [[nodiscard]] bool is_bottom() const { return num_bytes.is_bottom(); }

    [[nodiscard]] bool is_top() const { return num_bytes.is_top(); }

    bool operator<=(const array_domain_t& other) { return num_bytes <= other.num_bytes; }

    bool operator==(const array_domain_t& other) {
        return num_bytes == other.num_bytes;
    }

    void operator|=(const array_domain_t& other) {
        if (is_bottom()) {
            *this = other;
            return;
        }
        num_bytes |= other.num_bytes;
    }

    array_domain_t operator|(const array_domain_t& other) & {
        return array_domain_t(num_bytes | other.num_bytes);
    }

    array_domain_t operator|(const array_domain_t& other) && {
        return array_domain_t(num_bytes | other.num_bytes);
    }

    array_domain_t operator&(array_domain_t other) {
        return array_domain_t(num_bytes & other.num_bytes);
    }

    array_domain_t widen(const array_domain_t& other) {
        return array_domain_t(num_bytes | other.num_bytes);
    }

    array_domain_t widening_thresholds(const array_domain_t& other, const iterators::thresholds_t& ts) {
        return array_domain_t(num_bytes | other.num_bytes);
    }

    array_domain_t narrow(const array_domain_t& other) {
        return array_domain_t(num_bytes & other.num_bytes);
    }

    friend std::ostream& operator<<(std::ostream& o, const array_domain_t& dom) {
        return o << dom.num_bytes;
    }

    std::optional<linear_expression_t> load(NumAbsDomain& inv, data_kind_t kind, const linear_expression_t& i, int width);
    bool all_num(NumAbsDomain& inv, const linear_expression_t& lb, const linear_expression_t& ub);

    std::optional<variable_t> store(NumAbsDomain& inv, data_kind_t kind, const linear_expression_t& idx, const linear_expression_t& elem_size,
                                    const linear_expression_t& val);

    void havoc(NumAbsDomain& inv, data_kind_t kind, const linear_expression_t& idx, const linear_expression_t& elem_size) {
        auto maybe_cell = kill_and_find_var(inv, kind, idx, elem_size);
        if (maybe_cell && kind == data_kind_t::types) {
            auto [offset, size] = *maybe_cell;
            num_bytes.havoc(offset, size);
        }
    }

    // Perform array stores over an array segment
    void store_numbers(NumAbsDomain& inv, variable_t _idx, variable_t _width) {

        // TODO: this should be an user parameter.
        const number_t max_num_elems = EBPF_STACK_SIZE;

        if (is_bottom())
            return;

        std::optional<number_t> idx_n = inv[_idx].singleton();
        if (!idx_n) {
            CRAB_WARN("array expansion store range ignored because ", "lower bound is not constant");
            return;
        }

        std::optional<number_t> width = inv[_width].singleton();
        if (!width) {
            CRAB_WARN("array expansion store range ignored because ", "upper bound is not constant");
            return;
        }

        if (*idx_n + *width > max_num_elems) {
            CRAB_WARN("array expansion store range ignored because ",
                      "the number of elements is larger than default limit of ", max_num_elems);
            return;
        }
        num_bytes.reset((int)*idx_n, (int)*width);
    }

};

}
