#include "crab/array_expansion.hpp"

namespace crab {
namespace domains {
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

void offset_map_t::insert_cell(const cell_t& c, bool sanity_check) {
    if (sanity_check && !c.has_scalar()) {
        CRAB_ERROR("array expansion cannot insert a cell without scalar variable");
    }
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

cell_t offset_map_t::get_cell(offset_t o, unsigned size) const {
    if (std::optional<cell_set_t> cells = _map.lookup(o)) {
        cell_t tmp(o, size);
        auto it = (*cells).find(tmp);
        if (it != (*cells).end()) {
            return *it;
        }
    }
    // not found
    return cell_t();
}

std::string offset_map_t::mk_scalar_name(variable_t a, offset_t o, unsigned size) {
    crab_string_os os;
    os << a << "[";
    if (size == 1) {
        os << o;
    } else {
        os << o << "..." << o.index() + size - 1;
    }
    os << "]";
    return os.str();
}

cell_t offset_map_t::mk_cell(variable_t array, offset_t o, unsigned size) {
    // TODO: check array is the array associated to this offset map

    cell_t c = get_cell(o, size);
    if (c.is_null()) {
        auto& vfac = array.name().get_var_factory();
        std::string vname = mk_scalar_name(array, o, size);
        variable_type_t vtype = get_array_element_type(array.get_type());
        index_t vindex = get_index(array, o, size);

        // create a new scalar variable for representing the contents
        // of bytes array[o,o+1,..., o+size-1]
        variable_t scalar_var(vfac.get(vindex, vname), vtype, size);
        c = cell_t(o, scalar_var);
        insert_cell(c);
        CRAB_LOG("array-expansion", outs() << "**Created cell " << c << "\n";);
    }
    // sanity check
    if (!c.has_scalar()) {
        CRAB_ERROR("array expansion created a new cell without a scalar");
    }
    return c;
}

std::vector<cell_t> offset_map_t::get_all_cells() const {
    std::vector<cell_t> res;
    for (auto it = _map.begin(), et = _map.end(); it != et; ++it) {
        auto const& o_cells = it->second;
        for (auto& c : o_cells) {
            res.push_back(c);
        }
    }
    return res;
}

// Return in out all cells that might overlap with (o, size).
void offset_map_t::get_overlap_cells(offset_t o, unsigned size, std::vector<cell_t>& out) {
    compare_binding_t comp;

    bool added = false;
    cell_t c = get_cell(o, size);
    if (c.is_null()) {
        // we need to add a temporary cell for (o, size)
        c = cell_t(o, size);
        insert_cell(c, false /*disable sanity check*/);
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
                    if (!(x == c)) {
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
            if (x == c) { // we dont put it in out
                continue;
            }
            if (x.overlap(o, size)) {
                if (!(x == c)) {
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
        // remove the temporary cell for (o, size)
        assert(!c.is_null());
        remove_cell(c);
    }

    CRAB_LOG(
        "array-expansion-overlap", outs() << "**Overlap set between \n"
                                          << *this << "\nand "
                                          << "(" << o << "," << size << ")={";
        for (unsigned i = 0, e = out.size(); i < e;) {
            outs() << out[i];
            ++i;
            if (i < e) {
                outs() << ",";
            }
        } outs()
        << "}\n";);
}

void offset_map_t::write(crab_os& o) const {
    if (_map.empty()) {
        o << "empty";
    } else {
        for (auto it = _map.begin(), et = _map.end(); it != et; ++it) {
            const cell_set_t& cells = it->second;
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
}

std::map<std::pair<index_t, std::pair<offset_t, unsigned>>, index_t> offset_map_t::_index_map;
} // namespace domains
} // namespace crab