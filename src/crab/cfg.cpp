#include "crab/cfg.hpp"
#include "crab/types.hpp"

namespace crab {

void cfg_t::remove_useless_blocks() {
    if (!has_exit())
        return;

    cfg_rev_t rev_cfg(*this);

    visited_t useful, useless;
    mark_alive_blocks(rev_cfg.entry(), rev_cfg, useful);

    for (auto const& [label, bb] : *this) {
        if (!(useful.count(label) > 0)) {
            useless.insert(label);
        }
    }

    for (auto _label : useless) {
        remove(_label);
    }
}

basic_block_t& cfg_t::insert(label_t _label) {
    auto it = m_blocks.find(_label);
    if (it != m_blocks.end())
        return it->second;

    m_blocks.emplace(_label, _label);
    return get_node(_label);
}

void cfg_t::remove(label_t _label) {
    if (_label == m_entry) {
        CRAB_ERROR("Cannot remove entry block");
    }

    if (m_exit && *m_exit == _label) {
        CRAB_ERROR("Cannot remove exit block");
    }

    std::vector<std::pair<basic_block_t*, basic_block_t*>> dead_edges;
    auto& bb = get_node(_label);

    for (auto id : boost::make_iterator_range(bb.prev_blocks())) {
        if (_label != id) {
            dead_edges.push_back({&get_node(id), &bb});
        }
    }

    for (auto id : boost::make_iterator_range(bb.next_blocks())) {
        if (_label != id) {
            dead_edges.push_back({&bb, &get_node(id)});
        }
    }

    for (auto p : dead_edges) {
        (*p.first) -= (*p.second);
    }

    m_blocks.erase(_label);
}

void cfg_t::remove_unreachable_blocks() {
    visited_t alive, dead;
    mark_alive_blocks(entry(), *this, alive);

    for (auto const& [label, bb] : *this) {
        if (!(alive.count(label) > 0)) {
            dead.insert(label);
        }
    }

    for (auto _label : dead) {
        remove(_label);
    }
}

} // namespace crab