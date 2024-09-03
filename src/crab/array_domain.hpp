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

#include <functional>
#include <optional>
#include <utility>

#include <boost/container/flat_map.hpp>

#include "crab/add_bottom.hpp"
#include "crab/variable.hpp"

#include "crab/bitset_domain.hpp"

namespace crab::domains {

// Numerical abstract domain.
using NumAbsDomain = AddBottom;

using offset_t = index_t;
class offset_map_t;

/***
   Conceptually, a cell is tuple of an array, offset, size, and
   scalar variable such that:

_scalar = array[_offset, _offset + 1, ..., _offset + _size - 1]

    For simplicity, we don't carry the array inside the cell class.
    Only, offset_map objects can create cells. They will consider the
            array when generating the scalar variable.
*/
class cell_t final {
  private:
    friend class offset_map_t;
    friend std::ostream& operator<<(std::ostream& o, offset_map_t& m);
    offset_t _offset{};
    unsigned _size{};

    static interval_t to_interval(const offset_t o, unsigned size) {
        return {number_t{static_cast<int>(o)}, number_t{static_cast<int>(o)} + number_t{static_cast<int>(size - 1)}};
    }
    cell_t(offset_t offset, unsigned size) : _offset(offset), _size(size) {}

  public:
    // Only offset_map_t can create cells
    cell_t() = delete;

    [[nodiscard]]
    interval_t to_interval() const {
        return to_interval(_offset, _size);
    }

    [[nodiscard]]
    offset_t get_offset() const {
        return _offset;
    }

    [[nodiscard]]
    variable_t get_scalar(data_kind_t kind) const {
        return variable_t::cell_var(kind, number_t{_offset}, _size);
    }

    // ignore the scalar variable
    bool operator==(const cell_t& o) const { return to_interval() == o.to_interval(); }

    // ignore the scalar variable
    bool operator<(const cell_t& o) const {
        if (_offset == o._offset) {
            return _size < o._size;
        }
        return _offset < o._offset;
    }

    // Return true if [o, o + size) definitely overlaps with the cell,
    // where o is a constant expression.
    [[nodiscard]]
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
    bool symbolic_overlap(const linear_expression_t& symb_lb, const linear_expression_t& symb_ub,
                          const NumAbsDomain& dom) const;

    friend std::ostream& operator<<(std::ostream& o, const cell_t& c) { return o << "cell(" << c.to_interval() << ")"; }
};

// Map offsets to cells
class offset_map_t final {
  private:
    friend class array_domain_t;

    std::set<cell_t> set;

    void remove_cell(const cell_t& c);

    void insert_cell(const cell_t& c);

    [[nodiscard]]
    std::optional<cell_t> get_cell(offset_t o, unsigned size);

    cell_t mk_cell(offset_t o, unsigned size);

  public:
    offset_map_t() = default;

    [[nodiscard]]
    bool empty() const {
        return set.empty();
    }

    [[nodiscard]]
    std::size_t size() const {
        return set.size();
    }

    void operator-=(const cell_t& c) { remove_cell(c); }

    void operator-=(const std::vector<cell_t>& cells) {
        for (auto const& c : cells) {
            this->operator-=(c);
        }
    }

    // Return in out all cells that might overlap with (o, size).
    std::vector<cell_t> get_overlap_cells(offset_t o, unsigned size);

    [[nodiscard]]
    std::vector<cell_t> get_overlap_cells_symbolic_offset(const NumAbsDomain& dom, const linear_expression_t& symb_lb,
                                                          const linear_expression_t& symb_ub);

    friend std::ostream& operator<<(std::ostream& o, offset_map_t& m);

    /* Operations needed if used as value in a separate_domain */
    [[nodiscard]]
    bool is_top() const {
        return empty();
    }
    [[nodiscard]]
    bool is_bottom() const {
        return false;
    }
    /*
       We don't distinguish between bottom and top.
       This is fine because separate_domain only calls bottom if
       operator[] is called over a bottom state. Thus, we will make
       sure that we don't call operator[] in that case.
    */
    static offset_map_t bottom() { return {}; }
    static offset_map_t top() { return {}; }
    bool operator<=(const offset_map_t& other) const {
        return std::includes(set.begin(), set.end(), other.set.begin(), other.set.end());
    }
    bool operator==(const offset_map_t& other) const { return set == other.set; }
    offset_map_t operator|(const offset_map_t& other) const {
        offset_map_t res;
        std::set_union(set.begin(), set.end(), other.set.begin(), other.set.end(),
                       std::inserter(res.set, res.set.begin()));
        return res;
    }
    offset_map_t operator&(const offset_map_t& other) const {
        offset_map_t res;
        std::set_intersection(set.begin(), set.end(), other.set.begin(), other.set.end(),
                              std::inserter(res.set, res.set.begin()));
        return res;
    }
};

// map abstract domain. Lattice operations are memberwise.
class array_map_t {
    boost::container::flat_map<data_kind_t, offset_map_t> map;

  public:
    array_map_t() = default;

    [[nodiscard]]
    bool empty() const {
        return map.empty();
    }

    [[nodiscard]]
    std::size_t size() const {
        return map.size();
    }
    bool operator==(const array_map_t& other) const = default;

    offset_map_t& operator[](data_kind_t kind) { return map[kind]; }

    const offset_map_t& operator[](data_kind_t kind) const { return map.at(kind); }

    void operator-=(const cell_t& c) {
        for (auto& [_, v] : map) {
            v -= c;
        }
    }

    void operator-=(const std::vector<cell_t>& cells) {
        for (auto const& c : cells) {
            this->operator-=(c);
        }
    }

    [[nodiscard]]
    std::vector<cell_t> get_overlap_cells(data_kind_t kind, offset_t o, unsigned size) {
        auto it = map.find(kind);
        if (it != map.end()) {
            return it->second.get_overlap_cells(o, size);
        }
        return {};
    }

    [[nodiscard]]
    std::vector<cell_t> get_overlap_cells_symbolic_offset(data_kind_t kind, const NumAbsDomain& dom,
                                                          const linear_expression_t& symb_lb,
                                                          const linear_expression_t& symb_ub) {
        auto it = map.find(kind);
        if (it != map.end()) {
            return it->second.get_overlap_cells_symbolic_offset(dom, symb_lb, symb_ub);
        }
        return {};
    }

    array_map_t operator|(const array_map_t& other) const {
        array_map_t res;
        for (auto& [kind, offset_map] : map) {
            auto it = other.map.find(kind);
            if (it != other.map.end()) {
                res.map[kind] = offset_map | it->second;
            } else {
                res.map[kind] = offset_map;
            }
        }
        for (auto& [kind, offset_map] : other.map) {
            if (res.map.find(kind) == res.map.end()) {
                res.map[kind] = offset_map;
            }
        }
        return res;
    }

    array_map_t operator&(const array_map_t& other) const {
        array_map_t res;
        for (auto& [kind, offset_map] : map) {
            auto it = other.map.find(kind);
            if (it != other.map.end()) {
                res.map[kind] = offset_map & it->second;
            }
        }
        return res;
    }

    bool operator<=(const array_map_t& other) const {
        return std::ranges::all_of(map, [&other](const auto& p) {
            auto it = other.map.find(p.first);
            return it != other.map.end() && p.second <= it->second;
        });
    }

    array_map_t& operator|=(const array_map_t& other) {
        *this = *this | other;
        return *this;
    }
    void set_to_bottom() { map.clear(); }
};

class array_domain_t final {
    bitset_domain_t num_bytes;
    array_map_t array_map;

  public:
    array_domain_t() = default;

    array_domain_t(const bitset_domain_t& num_bytes, array_map_t array_map)
        : num_bytes(num_bytes), array_map(std::move(array_map)) {}

    void set_to_top();
    void set_to_bottom();
    [[nodiscard]]
    bool is_bottom() const;
    [[nodiscard]]
    bool is_top() const;

    bool operator<=(const array_domain_t& other) const;
    bool operator==(const array_domain_t& other) const;

    void operator|=(const array_domain_t& other);

    array_domain_t operator|(const array_domain_t& other) const;
    array_domain_t operator&(const array_domain_t& other) const;
    array_domain_t widen(const array_domain_t& other) const;
    array_domain_t widening_thresholds(const array_domain_t& other, const iterators::thresholds_t& ts) const;
    array_domain_t narrow(const array_domain_t& other) const;

    friend std::ostream& operator<<(std::ostream& o, const array_domain_t& dom);
    [[nodiscard]]
    string_invariant to_set() const;

    bool all_num(const NumAbsDomain& inv, const linear_expression_t& lb, const linear_expression_t& ub);
    [[nodiscard]]
    int min_all_num_size(const NumAbsDomain& inv, variable_t offset) const;

    std::optional<linear_expression_t> load(NumAbsDomain& inv, data_kind_t kind, const linear_expression_t& i,
                                            int width);
    std::optional<variable_t> store(NumAbsDomain& inv, data_kind_t kind, const linear_expression_t& idx,
                                    const linear_expression_t& elem_size, const linear_expression_t& val);
    std::optional<variable_t> store_type(NumAbsDomain& inv, const linear_expression_t& idx,
                                         const linear_expression_t& elem_size, const linear_expression_t& val);
    std::optional<variable_t> store_type(NumAbsDomain& inv, const linear_expression_t& idx,
                                         const linear_expression_t& elem_size, const Reg& reg);
    void havoc(NumAbsDomain& inv, data_kind_t kind, const linear_expression_t& idx,
               const linear_expression_t& elem_size);

    // Perform array stores over an array segment
    void store_numbers(const NumAbsDomain& inv, variable_t _idx, variable_t _width);

    void split_number_var(NumAbsDomain& inv, data_kind_t kind, const linear_expression_t& i,
                          const linear_expression_t& elem_size);
    void split_cell(NumAbsDomain& inv, data_kind_t kind, int cell_start_index, unsigned int len);

    void initialize_numbers(int lb, int width);

    std::optional<std::pair<offset_t, unsigned>> split_and_find_var(NumAbsDomain& inv, data_kind_t kind,
                                                                    const linear_expression_t& idx,
                                                                    const linear_expression_t& elem_size);
    std::optional<std::pair<offset_t, unsigned>> kill_and_find_var(NumAbsDomain& inv, data_kind_t kind,
                                                                   const linear_expression_t& i,
                                                                   const linear_expression_t& elem_size);
};

} // namespace crab::domains
