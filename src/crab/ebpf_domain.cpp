#include "crab/ebpf_domain.hpp"

namespace crab {
namespace domains {

// We use a global array map
array_map_t global_array_map;

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

        for (int i = upto_lb.size() - 1; i >= 0; --i) {
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

} // namespace domains
} // namespace crab