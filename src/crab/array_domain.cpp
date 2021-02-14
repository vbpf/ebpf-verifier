// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0

#include "crab/array_domain.hpp"

namespace crab::domains {

// We use a global array map
array_map_t global_array_map;

// Return true if [symb_lb, symb_ub] may overlap with the cell,
// where symb_lb and symb_ub are not constant expressions.
bool cell_t::symbolic_overlap(const linear_expression_t& symb_lb, const linear_expression_t& symb_ub,
                              const NumAbsDomain& dom) const {

    interval_t x = to_interval();
    assert(x.lb().is_finite());
    assert(x.ub().is_finite());
    linear_expression_t lb(*(x.lb().number()));
    linear_expression_t ub(*(x.ub().number()));

    NumAbsDomain tmp1(dom);
    using namespace dsl_syntax;
    tmp1 += lb >= symb_lb; //(lb >= symb_lb);
    tmp1 += lb <= symb_ub; //(lb <= symb_ub);
    if (!tmp1.is_bottom()) {
        CRAB_LOG("array-expansion-overlap", std::cout << "\tyes.\n";);
        return true;
    }

    NumAbsDomain tmp2(dom);
    tmp2 += ub >= symb_lb; // (ub >= symb_lb);
    tmp2 += ub <= symb_ub; // (ub <= symb_ub);
    if (!tmp2.is_bottom()) {
        CRAB_LOG("array-expansion-overlap", std::cout << "\tyes.\n";);
        return true;
    }

    CRAB_LOG("array-expansion-overlap", std::cout << "\tno.\n";);
    return false;
}

/**
    Ugly this needs to be fixed: needed if multiple analyses are
    run so we can clear the array map from one run to another.
**/
void clear_global_state() {
    if (!global_array_map.empty()) {
        if constexpr (crab::CrabSanityCheckFlag) {
            CRAB_WARN("array_expansion static variable map is being cleared");
        }
        global_array_map.clear();
    }
}

void offset_map_t::remove_cell(const cell_t& c) {
    if (std::optional<cell_set_t> cells = _map.lookup(c.get_offset())) {
        if ((*cells).erase(c) > 0) {
            _map.remove(c.get_offset());
            if (!(*cells).empty()) {
                // a bit of a waste ...
                _map.insert(c.get_offset(), *cells);
            }
        }
    }
}

[[nodiscard]]
std::vector<cell_t> offset_map_t::get_overlap_cells_symbolic_offset(const NumAbsDomain& dom,
                                                                    const linear_expression_t& symb_lb,
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

void offset_map_t::insert_cell(const cell_t& c) {
    if (std::optional<cell_set_t> cells = _map.lookup(c.get_offset())) {
        if ((*cells).insert(c).second) {
            // a bit of a waste ...
            _map.remove(c.get_offset());
            _map.insert(c.get_offset(), *cells);
        }
    } else {
        cell_set_t new_cells;
        new_cells.insert(c);
        _map.insert(c.get_offset(), new_cells);
    }
}

std::optional<cell_t> offset_map_t::get_cell(offset_t o, unsigned size) const {
    if (std::optional<cell_set_t> cells = _map.lookup(o)) {
        cell_t tmp(o, size);
        auto it = (*cells).find(tmp);
        if (it != (*cells).end()) {
            return *it;
        }
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
                if (!(x == *maybe_c)) {
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

    if (added) {
        remove_cell(*maybe_c);
    }
    return out;
}

std::ostream& operator<<(std::ostream& o, const offset_map_t& m) {
    if (m._map.empty()) {
        o << "empty";
    } else {
        for (auto it = m._map.begin(), et = m._map.end(); it != et; ++it) {
            const offset_map_t::cell_set_t& cells = it->second;
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

std::optional<std::pair<offset_t, unsigned>>
array_domain_t::kill_and_find_var(NumAbsDomain& inv, data_kind_t kind, const linear_expression_t& i, const linear_expression_t& elem_size) {
    std::optional<std::pair<offset_t, unsigned>> res;

    offset_map_t& offset_map = lookup_array_map(kind);
    interval_t ii = inv.eval_interval(i);
    std::vector<cell_t> cells;
    if (std::optional<number_t> n = ii.singleton()) {
        interval_t i_elem_size = inv.eval_interval(elem_size);
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
        cells = offset_map.get_overlap_cells_symbolic_offset(inv, linear_expression_t(i),
                                                             linear_expression_t(i + elem_size));
    }
    if (!cells.empty()) {
        // Forget the scalars from the numerical domain
        for (auto c : cells) {
            inv -= c.get_scalar(kind);
        }
        // Remove the cells. If needed again they they will be re-created.
        offset_map -= cells;
    }
    return res;
}

bool array_domain_t::all_num(NumAbsDomain& inv, const linear_expression_t& lb, const linear_expression_t& ub) {
    auto min_lb = inv.eval_interval(lb).lb().number();
    auto max_ub = inv.eval_interval(ub).ub().number();
    if (!min_lb || !max_ub || !min_lb->fits_sint() || !max_ub->fits_sint())
        return false;
    return this->num_bytes.all_num((int)*min_lb, (int)*max_ub);
}

std::optional<linear_expression_t> array_domain_t::load(NumAbsDomain& inv, data_kind_t kind, const linear_expression_t& i, int width) {
    interval_t ii = inv.eval_interval(i);
    if (std::optional<number_t> n = ii.singleton()) {
        offset_map_t& offset_map = lookup_array_map(kind);
        long k = (long)*n;
        if (kind == data_kind_t::types) {
            auto [only_num, only_non_num] = num_bytes.uniformity(k, width);
            if (only_num) {
                return T_NUM;
            }
            if (!only_non_num || width != 8) {
                return {};
            }
        }
        offset_t o(k);
        unsigned size = (long)width;
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
                Mine'06 to construct values of some type from a sequence
                of bytes. It can be endian-independent but it would more
                precise if we choose between little- and big-endian.
            */
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
            if (t && (long)*t == T_NUM)
                num_bytes.reset(offset, size);
            else
                num_bytes.havoc(offset, size);
        }
        variable_t v = lookup_array_map(kind).mk_cell(offset, size).get_scalar(kind);
        return v;
    }
    return {};
}

} // namespace crab::domains
