// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0

#include <algorithm>
#include <optional>
#include <set>
#include <unordered_map>
#include <utility>
#include <vector>

#include "radix_tree/radix_tree.hpp"
#include "crab/array_domain.hpp"

#include "asm_ostream.hpp"
#include "dsl_syntax.hpp"
#include "spec_type_descriptors.hpp"

namespace crab::domains {

static bool maybe_between(const NumAbsDomain& dom, const bound_t& x,
                          const linear_expression_t& symb_lb,
                          const linear_expression_t& symb_ub) {
    using namespace dsl_syntax;
    assert(x.is_finite());
    linear_expression_t num(*x.number());
    NumAbsDomain tmp(dom);
    tmp += num >= symb_lb;
    tmp += num <= symb_ub;
    return !tmp.is_bottom();
}

class offset_t final {
    index_t _index{};
    int _prefix_length;

  public:
    static constexpr int bitsize = 8 * sizeof(index_t);
    offset_t() : _prefix_length(bitsize) {}
    offset_t(index_t index) : _index(index), _prefix_length(bitsize) {}
    offset_t(index_t index, int prefix_length) : _index(index), _prefix_length(prefix_length) {}
    explicit operator int() const { return static_cast<int>(_index); }
    operator index_t() const { return _index; }
    [[nodiscard]] int prefix_length() const { return _prefix_length; }

    index_t operator[](int n) const { return (_index >> (bitsize - 1 - n)) & 1; }
};

// NOTE: required by radix_tree
// Get the length of a key, which is the size usable with the [] operator.
[[maybe_unused]]
int radix_length(const offset_t& offset) {
    return offset.prefix_length();
}

// NOTE: required by radix_tree
// Get a range of bits out of the middle of a key, starting at [begin] for a given length.
[[maybe_unused]]
offset_t radix_substr(const offset_t& key, int begin, int length)
{
    uint64_t mask;

    if (length == offset_t::bitsize)
        mask = 0;
    else
        mask = ((index_t)1) << length;

    mask -= 1;
    mask <<= offset_t::bitsize - length - begin;

    index_t value = (((index_t)key) & mask) << begin;
    return offset_t{value, length};
}

// NOTE: required by radix_tree
// Concatenate two bit patterns.
[[maybe_unused]]
offset_t radix_join(const offset_t& entry1, const offset_t& entry2)
{
    index_t value1 = (index_t)entry1;
    index_t value2 = (index_t)entry2;
    index_t value = value1 | (value2 >> entry1.prefix_length());
    int prefix_length = entry1.prefix_length() + entry2.prefix_length();

    return offset_t{value, prefix_length};
}

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

    offset_t _offset{};
    unsigned _size{};

    // Only offset_map_t can create cells
    cell_t() = default;

    cell_t(offset_t offset, unsigned size) : _offset(offset), _size(size) {}

    static interval_t to_interval(const offset_t o, unsigned size) {
        return {number_t{static_cast<int>(o)}, number_t{static_cast<int>(o)} + number_t{static_cast<int>(size - 1)}};
    }

    [[nodiscard]] interval_t to_interval() const { return to_interval(_offset, _size); }

  public:
    [[nodiscard]] bool is_null() const { return _offset == 0 && _size == 0; }

    [[nodiscard]] offset_t get_offset() const { return _offset; }

    [[nodiscard]] variable_t get_scalar(data_kind_t kind) const { return variable_t::cell_var(kind, number_t{_offset}, _size); }

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
    bool symbolic_overlap(const linear_expression_t& symb_lb,
                     const linear_expression_t& symb_ub,
                     const NumAbsDomain& dom) const;

    friend std::ostream& operator<<(std::ostream& o, const cell_t& c) { return o << "cell(" << c.to_interval() << ")"; }
};

// Return true if [symb_lb, symb_ub] may overlap with the cell,
// where symb_lb and symb_ub are not constant expressions.
bool cell_t::symbolic_overlap(const linear_expression_t& symb_lb, const linear_expression_t& symb_ub,
                              const NumAbsDomain& dom) const {
    interval_t x = to_interval();
    return maybe_between(dom, x.lb(), symb_lb, symb_ub)
        || maybe_between(dom, x.ub(), symb_lb, symb_ub);
}

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
    using patricia_tree_t = radix_tree<offset_t, cell_set_t>;

    patricia_tree_t _map;

    // for algorithm::lower_bound and algorithm::upper_bound
    struct compare_binding_t {
        bool operator()(const typename patricia_tree_t::value_type& kv, const offset_t& o) const { return kv.first < o; }
        bool operator()(const offset_t& o, const typename patricia_tree_t::value_type& kv) const { return o < kv.first; }
        bool operator()(const typename patricia_tree_t::value_type& kv1,
                        const typename patricia_tree_t::value_type& kv2) const {
            return kv1.first < kv2.first;
        }
    };

    void remove_cell(const cell_t& c);

    void insert_cell(const cell_t& c);

    [[nodiscard]] std::optional<cell_t> get_cell(offset_t o, unsigned size);

    cell_t mk_cell(offset_t o, unsigned size);

  public:
    offset_map_t() = default;

    [[nodiscard]] bool empty() const { return _map.empty(); }

    [[nodiscard]] std::size_t size() const { return _map.size(); }

    void operator-=(const cell_t& c) { remove_cell(c); }

    void operator-=(const std::vector<cell_t>& cells) {
        for (auto const& c : cells) {
            this->operator-=(c);
        }
    }

    // Return in out all cells that might overlap with (o, size).
    std::vector<cell_t> get_overlap_cells(offset_t o, unsigned size);

    [[nodiscard]] std::vector<cell_t> get_overlap_cells_symbolic_offset(const NumAbsDomain& dom,
                                                                        const linear_expression_t& symb_lb,
                                                                        const linear_expression_t& symb_ub);

    friend std::ostream& operator<<(std::ostream& o, offset_map_t& m);

    /* Operations needed if used as value in a separate_domain */
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

void offset_map_t::remove_cell(const cell_t& c) {
    offset_t key = c.get_offset();
    _map[key].erase(c);
}

[[nodiscard]]
std::vector<cell_t> offset_map_t::get_overlap_cells_symbolic_offset(const NumAbsDomain& dom,
                                                                    const linear_expression_t& symb_lb,
                                                                    const linear_expression_t& symb_ub) {
    std::vector<cell_t> out;
    for (const auto& [_offset, o_cells] : _map) {
        // All cells in o_cells have the same offset. They only differ in the size.
        // If the largest cell overlaps with [offset, offset + size)
        // then the rest of cells are considered to overlap.
        // This is an over-approximation because [offset, offset+size) can overlap
        // with the largest cell but it doesn't necessarily overlap with smaller cells.
        // For efficiency, we assume it overlaps with all.
        cell_t largest_cell;
        for (const cell_t& c : o_cells) {
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

void offset_map_t::insert_cell(const cell_t& c) {
    offset_t key = c.get_offset();
    _map[key].insert(c);
}

std::optional<cell_t> offset_map_t::get_cell(offset_t o, unsigned size) {
    cell_set_t& cells = _map[o];
    auto it = cells.find(cell_t(o, size));
    if (it != cells.end()) {
        return *it;
    }
    // not found
    return {};
}

cell_t offset_map_t::mk_cell(offset_t o, unsigned size) {
    // TODO: check array is the array associated to this offset map

    auto maybe_c = get_cell(o, size);
    if (maybe_c)
        return *maybe_c;
    // create a new scalar variable for representing the contents
    // of bytes array[o,o+1,..., o+size-1]
    cell_t c(o, size);
    insert_cell(c);
    return c;
}

// Return all cells that might overlap with (o, size).
std::vector<cell_t> offset_map_t::get_overlap_cells(offset_t o, unsigned size) {
    std::vector<cell_t> out;
    compare_binding_t comp;

    bool added = false;
    auto maybe_c = get_cell(o, size);
    if (!maybe_c) {
        maybe_c = cell_t(o, size);
        insert_cell(*maybe_c);
        added = true;
    }

    auto lb_it = std::lower_bound(_map.begin(), _map.end(), o, comp);
    if (lb_it != _map.end()) {
        // Store _map[begin,...,lb_it] into a vector so that we can
        // go backwards from lb_it.
        //
        // TODO: give support for reverse iterator in patricia_tree.
        std::vector<cell_set_t> upto_lb;
        upto_lb.reserve(std::distance(_map.begin(), lb_it));
        for (auto it = _map.begin(), et = lb_it; it != et; ++it) {
            upto_lb.push_back(it->second);
        }
        upto_lb.push_back(lb_it->second);

        for (int i = static_cast<int>(upto_lb.size() - 1); i >= 0; --i) {
            ///////
            // All the cells in upto_lb[i] have the same offset. They
            // just differ in the size.
            //
            // If none of the cells in upto_lb[i] overlap with (o, size)
            // we can stop.
            ////////
            bool continue_outer_loop = false;
            for (const cell_t& x : upto_lb[i]) {
                if (x.overlap(o, size)) {
                    if (!(x == *maybe_c)) {
                        // FIXME: we might have some duplicates. this is a very drastic solution.
                        if (std::find(out.begin(), out.end(), x) == out.end()) {
                            out.push_back(x);
                        }
                    }
                    continue_outer_loop = true;
                }
            }
            if (!continue_outer_loop) {
                break;
            }
        }
    }

    // search for overlapping cells > o
    auto ub_it = std::upper_bound(_map.begin(), _map.end(), o, comp);
    for (; ub_it != _map.end(); ++ub_it) {
        bool continue_outer_loop = false;
        for (const cell_t& x : ub_it->second) {
            if (x.overlap(o, size)) {
                // FIXME: we might have some duplicates. this is a very drastic solution.
                if (std::find(out.begin(), out.end(), x) == out.end()) {
                    out.push_back(x);
                }
                continue_outer_loop = true;
            }
        }
        if (!continue_outer_loop) {
            break;
        }
    }

    // do not forget the rest of overlapping cells == o
    for (auto it = ++lb_it, et = ub_it; it != et; ++it) {
        bool continue_outer_loop = false;
        for (const cell_t& x : it->second) {
            if (x == *maybe_c) { // we dont put it in out
                continue;
            }
            if (x.overlap(o, size)) {
                if (std::find(out.begin(), out.end(), x) == out.end()) {
                    out.push_back(x);
                }
                continue_outer_loop = true;
            }
        }
        if (!continue_outer_loop) {
            break;
        }
    }

    if (added) {
        remove_cell(*maybe_c);
    }
    return out;
}

// We use a global array map
using array_map_t = std::unordered_map<data_kind_t, offset_map_t>;

static thread_local crab::lazy_allocator<array_map_t> global_array_map;

void clear_thread_local_state()
{
    global_array_map.clear();
}

static offset_map_t& lookup_array_map(data_kind_t kind) {
    return (*global_array_map)[kind];
}

/**
    Ugly this needs to be fixed: needed if multiple analyses are
    run so we can clear the array map from one run to another.
**/
void clear_global_state() {
    if (!global_array_map->empty()) {
        if constexpr (crab::CrabSanityCheckFlag) {
            CRAB_WARN("array_expansion static variable map is being cleared");
        }
        global_array_map->clear();
    }
}

void array_domain_t::initialize_numbers(int lb, int width) {
    num_bytes.reset(lb, width);
    lookup_array_map(data_kind_t::svalues).mk_cell(lb, width);
}

std::ostream& operator<<(std::ostream& o, offset_map_t& m) {
    if (m._map.empty()) {
        o << "empty";
    } else {
        for (const auto& [_offset, cells] : m._map) {
            o << "{";
            for (auto cit = cells.begin(), cet = cells.end(); cit != cet;) {
                o << *cit;
                ++cit;
                if (cit != cet) {
                    o << ",";
                }
            }
            o << "}\n";
        }
    }
    return o;
}

// we can only treat this as non-member because we use global state
static std::optional<std::pair<offset_t, unsigned>>
kill_and_find_var(NumAbsDomain& inv, data_kind_t kind, const linear_expression_t& i, const linear_expression_t& elem_size) {
    std::optional<std::pair<offset_t, unsigned>> res;

    offset_map_t& offset_map = lookup_array_map(kind);
    interval_t ii = inv.eval_interval(i);
    std::vector<cell_t> cells;
    if (std::optional<number_t> n = ii.singleton()) {
        interval_t i_elem_size = inv.eval_interval(elem_size);
        std::optional<number_t> n_bytes = i_elem_size.singleton();
        if (n_bytes) {
            auto size = static_cast<unsigned int>(*n_bytes);
            // -- Constant index: kill overlapping cells
            offset_t o((uint64_t)*n);
            cells = offset_map.get_overlap_cells(o, size);
            res = std::make_pair(o, size);
        }
    }
    if (!res) {
        // -- Non-constant index: kill overlapping cells
        cells = offset_map.get_overlap_cells_symbolic_offset(inv, i, i.plus(elem_size));
    }
    if (!cells.empty()) {
        // Forget the scalars from the numerical domain
        for (auto const& c : cells) {
            inv -= c.get_scalar(kind);

            // Forget signed and unsigned values together.
            if (kind == data_kind_t::svalues) {
                inv -= c.get_scalar(data_kind_t::uvalues);
            } else if (kind == data_kind_t::uvalues) {
                inv -= c.get_scalar(data_kind_t::svalues);
            }
        }
        // Remove the cells. If needed again they will be re-created.
        offset_map -= cells;
    }
    return res;
}

bool array_domain_t::all_num(NumAbsDomain& inv, const linear_expression_t& lb, const linear_expression_t& ub) {
    auto min_lb = inv.eval_interval(lb).lb().number();
    auto max_ub = inv.eval_interval(ub).ub().number();
    if (!min_lb || !max_ub || !min_lb->fits_sint32() || !max_ub->fits_sint32())
        return false;
    return this->num_bytes.all_num((int32_t)*min_lb, (int32_t)*max_ub);
}

// Get the number of bytes, starting at offset, that are known to be numbers.
int array_domain_t::min_all_num_size(const NumAbsDomain& inv, variable_t offset) const {
    auto min_lb = inv.eval_interval(offset).lb().number();
    auto max_ub = inv.eval_interval(offset).ub().number();
    if (!min_lb || !max_ub || !min_lb->fits_sint32() || !max_ub->fits_sint32())
        return 0;
    auto lb = (int)min_lb.value();
    auto ub = (int)max_ub.value();
    return std::max(0, this->num_bytes.all_num_width(lb) - (ub - lb));
}

// Get one byte of a value.
std::optional<uint8_t> get_value_byte(NumAbsDomain& inv, offset_t o, int width) {
    variable_t v = variable_t::cell_var(data_kind_t::svalues, (o / width) * width, width);
    std::optional<number_t> t = inv.eval_interval(v).singleton();
    if (!t) {
        return {};
    }
    uint64_t n = t->cast_to_uint64();
    uint8_t* bytes = (uint8_t*)&n;
    return bytes[o % width];
}

std::optional<linear_expression_t> array_domain_t::load(NumAbsDomain& inv, data_kind_t kind, const linear_expression_t& i, int width) {
    interval_t ii = inv.eval_interval(i);
    if (std::optional<number_t> n = ii.singleton()) {
        offset_map_t& offset_map = lookup_array_map(kind);
        int64_t k = (int64_t)*n;
        if (kind == data_kind_t::types) {
            auto [only_num, only_non_num] = num_bytes.uniformity(k, width);
            if (only_num) {
                return number_t{T_NUM};
            }
            if (!only_non_num || width != 8) {
                return {};
            }
        }
        offset_t o(k);
        unsigned size = (long)width;
        if (auto cell = lookup_array_map(kind).get_cell(o, size)) {
            return cell->get_scalar(kind);
        }
        if ((kind == data_kind_t::svalues) || (kind == data_kind_t::uvalues)) {
            // Copy bytes into result_buffer, taking into account that the
            // bytes might be in different stack variables and might be unaligned.
            uint8_t result_buffer[8];
            bool found = true;
            for (unsigned int index = 0; index < size; index++) {
                offset_t byte_offset = o + index;
                std::optional<uint8_t> b = get_value_byte(inv, byte_offset, 8);
                if (!b) {
                    b = get_value_byte(inv, byte_offset, 4);
                    if (!b) {
                        b = get_value_byte(inv, byte_offset, 2);
                        if (!b) {
                            b = get_value_byte(inv, byte_offset, 1);
                        }
                    }
                }
                if (b) {
                    result_buffer[index] = *b;
                } else {
                    found = false;
                    break;
                }
            }
            if (found) {
                // We have an aligned result in result_buffer so we can now
                // convert to an integer.
                if (size == 1) {
                    uint8_t b = *result_buffer;
                    return number_t{b};
                }
                if (size == 2) {
                    uint16_t b = *(uint16_t*)result_buffer;
                    return number_t{b};
                }
                if (size == 4) {
                    uint32_t b = *(uint32_t*)result_buffer;
                    return number_t{b};
                }
                if (size == 8) {
                    uint64_t b = *(uint64_t*)result_buffer;
                    return (kind == data_kind_t::uvalues) ? number_t(b) : number_t((int64_t)b);
                }
            }
        }

        std::vector<cell_t> cells = offset_map.get_overlap_cells(o, size);
        if (cells.empty()) {
            cell_t c = offset_map.mk_cell(o, size);
            // Here it's ok to do assignment (instead of expand)
            // because c is not a summarized variable. Otherwise, it
            // would be unsound.
            return c.get_scalar(kind);
        } else {
            CRAB_WARN("Ignored read from cell ", kind, "[", o, "...", o + size - 1, "]",
                      " because it overlaps with ", cells.size(), " cells");
            /*
                TODO: we can apply here "Value Recomposition" 'a la'
                Mine'06 (https://arxiv.org/pdf/cs/0703074.pdf)
                to construct values of some type from a sequence
                of bytes. It can be endian-independent but it would more
                precise if we choose between little- and big-endian.
            */
        }
    } else if (kind == data_kind_t::types) {
        // Check whether the kind is uniform across the entire interval.
        auto lb = ii.lb().number();
        auto ub = ii.ub().number();
        if (lb.has_value() && ub.has_value()) {
            z_number fullwidth = ub.value() - lb.value() + width;
            if (lb.value().fits_uint32() && fullwidth.fits_uint32()) {
                auto [only_num, only_non_num] = num_bytes.uniformity((uint32_t)lb.value(), (uint32_t)fullwidth);
                if (only_num) {
                    return number_t{T_NUM};
                }
            }
        }
    } else {
        // TODO: we can be more precise here
        CRAB_WARN("array expansion: ignored array load because of non-constant array index ", i);
    }
    return {};
}

std::optional<variable_t> array_domain_t::store(NumAbsDomain& inv, data_kind_t kind,
                                                const linear_expression_t& idx,
                                                const linear_expression_t& elem_size,
                                                const linear_expression_t& val) {
    auto maybe_cell = kill_and_find_var(inv, kind, idx, elem_size);
    if (maybe_cell) {
        // perform strong update
        auto [offset, size] = *maybe_cell;
        if (kind == data_kind_t::types) {
            std::optional<number_t> t = inv.eval_interval(val).singleton();
            if (t && (int64_t)*t == T_NUM)
                num_bytes.reset(offset, size);
            else
                num_bytes.havoc(offset, size);
        }
        variable_t v = lookup_array_map(kind).mk_cell(offset, size).get_scalar(kind);
        return v;
    }
    return {};
}

std::optional<variable_t> array_domain_t::store_type(NumAbsDomain& inv,
                                                     const linear_expression_t& idx,
                                                     const linear_expression_t& elem_size,
                                                     const linear_expression_t& val) {
    auto kind = data_kind_t::types;
    auto maybe_cell = kill_and_find_var(inv, kind, idx, elem_size);
    if (maybe_cell) {
        // perform strong update
        auto [offset, size] = *maybe_cell;
        std::optional<number_t> t = inv.eval_interval(val).singleton();
        if (t && (int64_t)*t == T_NUM)
            num_bytes.reset(offset, size);
        else
            num_bytes.havoc(offset, size);
        variable_t v = lookup_array_map(kind).mk_cell(offset, size).get_scalar(kind);
        return v;
    }
    return {};
}

std::optional<variable_t> array_domain_t::store_type(NumAbsDomain& inv,
                                                     const linear_expression_t& idx,
                                                     const linear_expression_t& elem_size,
                                                     const Reg& reg) {
    return store_type(inv, idx, elem_size, variable_t::reg(data_kind_t::types, reg.v));
}

void array_domain_t::havoc(NumAbsDomain& inv, data_kind_t kind, const linear_expression_t& idx, const linear_expression_t& elem_size) {
    auto maybe_cell = kill_and_find_var(inv, kind, idx, elem_size);
    if (maybe_cell && kind == data_kind_t::types) {
        auto [offset, size] = *maybe_cell;
        num_bytes.havoc(offset, size);
    }
}

void array_domain_t::store_numbers(NumAbsDomain& inv, variable_t _idx, variable_t _width) {

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

void array_domain_t::set_to_top() {
    num_bytes.set_to_top();
}

void array_domain_t::set_to_bottom() { num_bytes.set_to_bottom(); }

bool array_domain_t::is_bottom() const { return num_bytes.is_bottom(); }

bool array_domain_t::is_top() const { return num_bytes.is_top(); }

string_invariant array_domain_t::to_set() const { return num_bytes.to_set(); }

bool array_domain_t::operator<=(const array_domain_t& other) const { return num_bytes <= other.num_bytes; }

bool array_domain_t::operator==(const array_domain_t& other) const {
    return num_bytes == other.num_bytes;
}

void array_domain_t::operator|=(const array_domain_t& other) {
    if (is_bottom()) {
        *this = other;
        return;
    }
    num_bytes |= other.num_bytes;
}

array_domain_t array_domain_t::operator|(const array_domain_t& other) const {
    return array_domain_t(num_bytes | other.num_bytes);
}

array_domain_t array_domain_t::operator&(const array_domain_t& other) const {
    return array_domain_t(num_bytes & other.num_bytes);
}

array_domain_t array_domain_t::widen(const array_domain_t& other) const {
    return array_domain_t(num_bytes | other.num_bytes);
}

array_domain_t array_domain_t::widening_thresholds(const array_domain_t& other, const iterators::thresholds_t& ts) const {
    return array_domain_t(num_bytes | other.num_bytes);
}

array_domain_t array_domain_t::narrow(const array_domain_t& other) const {
    return array_domain_t(num_bytes & other.num_bytes);
}

std::ostream& operator<<(std::ostream& o, const array_domain_t& dom) {
    return o << dom.num_bytes;
}
} // namespace crab::domains
