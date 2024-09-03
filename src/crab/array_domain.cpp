// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0

#include <algorithm>
#include <optional>
#include <set>
#include <utility>
#include <vector>

#include "boost/endian/conversion.hpp"

#include "crab/array_domain.hpp"
#include "radix_tree/radix_tree.hpp"

#include "asm_ostream.hpp"
#include "config.hpp"
#include "dsl_syntax.hpp"
#include "spec_type_descriptors.hpp"

namespace crab::domains {

static bool maybe_between(const NumAbsDomain& dom, const bound_t& x, const linear_expression_t& symb_lb,
                          const linear_expression_t& symb_ub) {
    using namespace dsl_syntax;
    assert(x.is_finite());
    linear_expression_t num(*x.number());
    NumAbsDomain tmp(dom);
    tmp += num >= symb_lb;
    tmp += num <= symb_ub;
    return !tmp.is_bottom();
}

// Return true if [symb_lb, symb_ub] may overlap with the cell,
// where symb_lb and symb_ub are not constant expressions.
bool cell_t::symbolic_overlap(const linear_expression_t& symb_lb, const linear_expression_t& symb_ub,
                              const NumAbsDomain& dom) const {
    interval_t x = to_interval();
    return maybe_between(dom, x.lb(), symb_lb, symb_ub) || maybe_between(dom, x.ub(), symb_lb, symb_ub);
}

void offset_map_t::remove_cell(const cell_t& c) { set.erase(c); }

[[nodiscard]]
std::vector<cell_t> offset_map_t::get_overlap_cells_symbolic_offset(const NumAbsDomain& dom,
                                                                    const linear_expression_t& symb_lb,
                                                                    const linear_expression_t& symb_ub) {
    std::vector<cell_t> out;
    for (const auto& cell : set) {
        if (cell.symbolic_overlap(symb_lb, symb_ub, dom)) {
            out.push_back(cell);
        }
    }
    return out;
}

void offset_map_t::insert_cell(const cell_t& c) { set.insert(c); }

std::optional<cell_t> offset_map_t::get_cell(offset_t o, unsigned size) {
    cell_t res{o, size};
    if (!set.contains(res)) {
        return {};
    }
    return res;
}

cell_t offset_map_t::mk_cell(offset_t o, unsigned size) {
    // TODO: check array is the array associated to this offset map

    auto maybe_c = get_cell(o, size);
    if (maybe_c) {
        return *maybe_c;
    }
    // create a new scalar variable for representing the contents
    // of bytes array[o,o+1,..., o+size-1]
    cell_t c(o, size);
    insert_cell(c);
    return c;
}

// Return all cells that might overlap with (o, size).
std::vector<cell_t> offset_map_t::get_overlap_cells(offset_t o, unsigned size) {
    std::vector<cell_t> out;
    for (const cell_t& c : set) {
        if (c.overlap(o, size)) {
            out.push_back(c);
        }
    }
    return out;
}

void array_domain_t::initialize_numbers(int lb, int width) {
    num_bytes.reset(lb, width);
    array_map[data_kind_t::svalues].mk_cell(lb, width);
}

std::ostream& operator<<(std::ostream& o, offset_map_t& m) {
    if (m.set.empty()) {
        o << "empty";
    } else {
        bool first = true;
        o << "{";
        for (const cell_t& cell : m.set) {
            o << cell;
            if (!first) {
                o << ",";
            }
            first = false;
        }
        o << "}\n";
    }
    return o;
}

// Create a new cell that is a subset of an existing cell.
void array_domain_t::split_cell(NumAbsDomain& inv, data_kind_t kind, int cell_start_index, unsigned int len) {
    assert(kind == data_kind_t::svalues || kind == data_kind_t::uvalues);

    // Get the values from the indicated stack range.
    std::optional<linear_expression_t> svalue = load(inv, data_kind_t::svalues, number_t(cell_start_index), len);
    std::optional<linear_expression_t> uvalue = load(inv, data_kind_t::uvalues, number_t(cell_start_index), len);

    // Create a new cell for that range.
    cell_t new_cell = array_map[kind].mk_cell(cell_start_index, len);
    inv.assign(new_cell.get_scalar(data_kind_t::svalues), svalue);
    inv.assign(new_cell.get_scalar(data_kind_t::uvalues), uvalue);
}

// Prepare to havoc bytes in the middle of a cell by potentially splitting the cell if it is numeric,
// into the part to the left of the havoced portion, and the part to the right of the havoced portion.
void array_domain_t::split_number_var(NumAbsDomain& inv, data_kind_t kind, const linear_expression_t& i,
                                      const linear_expression_t& elem_size) {
    assert(kind == data_kind_t::svalues || kind == data_kind_t::uvalues);
    offset_map_t& offset_map = array_map[kind];
    interval_t ii = inv.eval_interval(i);
    std::optional<number_t> n = ii.singleton();
    if (!n) {
        // We can only split a singleton offset.
        return;
    }
    interval_t i_elem_size = inv.eval_interval(elem_size);
    std::optional<number_t> n_bytes = i_elem_size.singleton();
    if (!n_bytes) {
        // We can only split a singleton size.
        return;
    }
    auto size = static_cast<unsigned int>(*n_bytes);
    offset_t o((uint64_t)*n);

    std::vector<cell_t> cells = offset_map.get_overlap_cells(o, size);
    for (cell_t const& c : cells) {
        interval_t intv = c.to_interval();
        int cell_start_index = (int)*intv.lb().number();
        int cell_end_index = (int)*intv.ub().number();

        if (!this->num_bytes.all_num(cell_start_index, cell_end_index + 1) ||
            (cell_end_index + 1 < cell_start_index + sizeof(int64_t))) {
            // We can only split numeric cells of size 8 or less.
            continue;
        }

        if (!inv.eval_interval(c.get_scalar(kind)).is_singleton()) {
            // We can only split cells with a singleton value.
            continue;
        }
        if (cell_start_index < o) {
            // Use the bytes to the left of the specified range.
            split_cell(inv, kind, cell_start_index, (unsigned int)(o - cell_start_index));
        }
        if (o + size - 1 < cell_end_index) {
            // Use the bytes to the right of the specified range.
            split_cell(inv, kind, (int)(o + size), (unsigned int)(cell_end_index - (o + size - 1)));
        }
    }
}

// we can only treat this as non-member because we use global state
std::optional<std::pair<offset_t, unsigned>> array_domain_t::kill_and_find_var(NumAbsDomain& inv, data_kind_t kind,
                                                                               const linear_expression_t& i,
                                                                               const linear_expression_t& elem_size) {
    std::optional<std::pair<offset_t, unsigned>> res;

    offset_map_t& offset_map = array_map[kind];
    interval_t ii = inv.eval_interval(i);
    std::vector<cell_t> cells;
    if (std::optional<number_t> n = ii.singleton()) {
        interval_t i_elem_size = inv.eval_interval(elem_size);
        std::optional<number_t> n_bytes = i_elem_size.singleton();
        if (n_bytes) {
            auto size = static_cast<unsigned int>(*n_bytes);
            // -- Constant index: kill overlapping cells
            auto o((uint64_t)*n);
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

bool array_domain_t::all_num(const NumAbsDomain& inv, const linear_expression_t& lb, const linear_expression_t& ub) {
    auto min_lb = inv.eval_interval(lb).lb().number();
    auto max_ub = inv.eval_interval(ub).ub().number();
    if (!min_lb || !max_ub || !min_lb->fits_sint32() || !max_ub->fits_sint32()) {
        return false;
    }

    // The all_num() call requires a legal range. If we have an illegal range,
    // we should have already generated an error about the invalid range so just
    // return true now to avoid an extra error about a non-numeric range.
    if (*min_lb >= *max_ub) {
        return true;
    }

    return this->num_bytes.all_num((int32_t)*min_lb, (int32_t)*max_ub);
}

// Get the number of bytes, starting at offset, that are known to be numbers.
int array_domain_t::min_all_num_size(const NumAbsDomain& inv, variable_t offset) const {
    auto min_lb = inv.eval_interval(offset).lb().number();
    auto max_ub = inv.eval_interval(offset).ub().number();
    if (!min_lb || !max_ub || !min_lb->fits_sint32() || !max_ub->fits_sint32()) {
        return 0;
    }
    auto lb = (int)min_lb.value();
    auto ub = (int)max_ub.value();
    return std::max(0, this->num_bytes.all_num_width(lb) - (ub - lb));
}

// Get one byte of a value.
std::optional<uint8_t> get_value_byte(const NumAbsDomain& inv, offset_t o, int width) {
    variable_t v = variable_t::cell_var(data_kind_t::svalues, (o / width) * width, width);
    std::optional<number_t> t = inv.eval_interval(v).singleton();
    if (!t) {
        return {};
    }
    uint64_t n = t->cast_to_uint64();

    // Convert value to bytes of the appropriate endian-ness.
    switch (width) {
    case sizeof(uint16_t):
        if (thread_local_options.big_endian) {
            n = boost::endian::native_to_big<uint16_t>(n);
        } else {
            n = boost::endian::native_to_little<uint16_t>(n);
        }
        break;
    case sizeof(uint32_t):
        if (thread_local_options.big_endian) {
            n = boost::endian::native_to_big<uint32_t>(n);
        } else {
            n = boost::endian::native_to_little<uint32_t>(n);
        }
        break;
    case sizeof(uint64_t):
        if (thread_local_options.big_endian) {
            n = boost::endian::native_to_big<uint64_t>(n);
        } else {
            n = boost::endian::native_to_little<uint64_t>(n);
        }
        break;
    }
    auto* bytes = (uint8_t*)&n;
    return bytes[o % width];
}

std::optional<linear_expression_t> array_domain_t::load(NumAbsDomain& inv, data_kind_t kind,
                                                        const linear_expression_t& i, int width) {
    interval_t ii = inv.eval_interval(i);
    if (std::optional<number_t> n = ii.singleton()) {
        offset_map_t& offset_map = array_map[kind];
        auto k = (int64_t)*n;
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
        if (auto cell = array_map[kind].get_cell(o, size)) {
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
                    if (thread_local_options.big_endian) {
                        b = boost::endian::native_to_big<uint16_t>(b);
                    } else {
                        b = boost::endian::native_to_little<uint16_t>(b);
                    }
                    return number_t{b};
                }
                if (size == 4) {
                    uint32_t b = *(uint32_t*)result_buffer;
                    if (thread_local_options.big_endian) {
                        b = boost::endian::native_to_big<uint32_t>(b);
                    } else {
                        b = boost::endian::native_to_little<uint32_t>(b);
                    }
                    return number_t{b};
                }
                if (size == 8) {
                    uint64_t b = *(uint64_t*)result_buffer;
                    if (thread_local_options.big_endian) {
                        b = boost::endian::native_to_big<uint64_t>(b);
                    } else {
                        b = boost::endian::native_to_little<uint64_t>(b);
                    }
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
            CRAB_WARN("Ignored read from cell ", kind, "[", o, "...", o + size - 1, "]", " because it overlaps with ",
                      cells.size(), " cells");
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

// We are about to write to a given range of bytes on the stack.
// Any cells covering that range need to be removed, and any cells that only
// partially cover that range can be split such that any non-covered portions become new cells.
std::optional<std::pair<offset_t, unsigned>> array_domain_t::split_and_find_var(NumAbsDomain& inv, data_kind_t kind,
                                                                                const linear_expression_t& idx,
                                                                                const linear_expression_t& elem_size) {
    if (kind == data_kind_t::svalues || kind == data_kind_t::uvalues) {
        this->split_number_var(inv, kind, idx, elem_size);
    }
    return kill_and_find_var(inv, kind, idx, elem_size);
}

std::optional<variable_t> array_domain_t::store(NumAbsDomain& inv, data_kind_t kind, const linear_expression_t& idx,
                                                const linear_expression_t& elem_size, const linear_expression_t& val) {
    auto maybe_cell = split_and_find_var(inv, kind, idx, elem_size);
    if (maybe_cell) {
        // perform strong update
        auto [offset, size] = *maybe_cell;
        if (kind == data_kind_t::types) {
            std::optional<number_t> t = inv.eval_interval(val).singleton();
            if (t && (int64_t)*t == T_NUM) {
                num_bytes.reset(offset, size);
            } else {
                num_bytes.havoc(offset, size);
            }
        }
        variable_t v = array_map[kind].mk_cell(offset, size).get_scalar(kind);
        return v;
    }
    return {};
}

std::optional<variable_t> array_domain_t::store_type(NumAbsDomain& inv, const linear_expression_t& idx,
                                                     const linear_expression_t& elem_size,
                                                     const linear_expression_t& val) {
    auto kind = data_kind_t::types;
    auto maybe_cell = split_and_find_var(inv, kind, idx, elem_size);
    if (maybe_cell) {
        // perform strong update
        auto [offset, size] = *maybe_cell;
        std::optional<number_t> t = inv.eval_interval(val).singleton();
        if (t && (int64_t)*t == T_NUM) {
            num_bytes.reset(offset, size);
        } else {
            num_bytes.havoc(offset, size);
        }
        variable_t v = array_map[kind].mk_cell(offset, size).get_scalar(kind);
        return v;
    }
    return {};
}

std::optional<variable_t> array_domain_t::store_type(NumAbsDomain& inv, const linear_expression_t& idx,
                                                     const linear_expression_t& elem_size, const Reg& reg) {
    return store_type(inv, idx, elem_size, variable_t::reg(data_kind_t::types, reg.v));
}

void array_domain_t::havoc(NumAbsDomain& inv, data_kind_t kind, const linear_expression_t& idx,
                           const linear_expression_t& elem_size) {
    auto maybe_cell = split_and_find_var(inv, kind, idx, elem_size);
    if (maybe_cell && kind == data_kind_t::types) {
        auto [offset, size] = *maybe_cell;
        num_bytes.havoc(offset, size);
    }
}

void array_domain_t::store_numbers(const NumAbsDomain& inv, variable_t _idx, variable_t _width) {

    // TODO: this should be an user parameter.
    const number_t max_num_elems = EBPF_STACK_SIZE;

    if (is_bottom()) {
        return;
    }

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

void array_domain_t::set_to_top() { num_bytes.set_to_top(); }

void array_domain_t::set_to_bottom() {
    num_bytes.set_to_bottom();
    array_map.set_to_bottom();
}

bool array_domain_t::is_bottom() const { return num_bytes.is_bottom(); }

bool array_domain_t::is_top() const { return num_bytes.is_top(); }

string_invariant array_domain_t::to_set() const { return num_bytes.to_set(); }

bool array_domain_t::operator<=(const array_domain_t& other) const {
    return num_bytes <= other.num_bytes && array_map <= other.array_map;
}

bool array_domain_t::operator==(const array_domain_t& other) const {
    return num_bytes == other.num_bytes && array_map == other.array_map;
}

void array_domain_t::operator|=(const array_domain_t& other) {
    if (is_bottom()) {
        *this = other;
        return;
    }
    num_bytes |= other.num_bytes;
    array_map |= other.array_map;
}

array_domain_t array_domain_t::operator|(const array_domain_t& other) const {
    return array_domain_t(num_bytes | other.num_bytes, array_map | other.array_map);
}

array_domain_t array_domain_t::operator&(const array_domain_t& other) const {
    return array_domain_t(num_bytes & other.num_bytes, array_map & other.array_map);
}

array_domain_t array_domain_t::widen(const array_domain_t& other) const {
    return array_domain_t(num_bytes | other.num_bytes, array_map | other.array_map);
}

array_domain_t array_domain_t::widening_thresholds(const array_domain_t& other,
                                                   const iterators::thresholds_t& ts) const {
    return array_domain_t(num_bytes | other.num_bytes, array_map | other.array_map);
}

array_domain_t array_domain_t::narrow(const array_domain_t& other) const {
    return array_domain_t(num_bytes & other.num_bytes, array_map & other.array_map);
}

std::ostream& operator<<(std::ostream& o, const array_domain_t& dom) { return o << dom.num_bytes; }
} // namespace crab::domains
