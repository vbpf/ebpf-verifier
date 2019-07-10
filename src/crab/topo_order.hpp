#pragma once

#include "crab/sccg.hpp"
#include "crab/sccg_bgl.hpp"

#include <boost/graph/topological_sort.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/unordered_map.hpp>

/*
   Topological order of a graph
 */

namespace crab {
namespace analyzer {
namespace graph_algo {

// res contains the reverse topological order of a graph g
// pre: g is a DAG.
template <typename G>
void rev_topo_sort(const G &g, std::vector<typename G::node_t> &res) {

    using color_map_t = boost::unordered_map<typename G::node_t, boost::default_color_type>;
    using property_color_map_t = boost::associative_property_map<color_map_t>;

    color_map_t colormap;

    for (auto const &v : boost::make_iterator_range(vertices(g))) {
        colormap[v] = boost::default_color_type();
    }

    res.reserve(num_vertices(g));

    boost::topological_sort(g, std::back_inserter(res), color_map(property_color_map_t(colormap)));
}

// res contains the topological order of g.
// pre: g is a DAG.
template <typename G>
void topo_sort(const G &g, std::vector<typename G::node_t> &res) {
    rev_topo_sort(g, res);
    std::reverse(res.begin(), res.end());
}

// return the reversed topological order of g with possibly cycles.
// XXX: related concept but this is not Bourdoncle's WTO
template <class G>
std::vector<typename G::node_t> weak_rev_topo_sort(G g) {
    std::vector<typename G::node_t> sccg_order;
    scc_graph<G> scc_g(g, false /*postorder within scc*/);
    rev_topo_sort(scc_g, sccg_order);
    std::vector<typename G::node_t> order;
    for (auto &n : sccg_order) {
        auto &members = scc_g.get_component_members(n);
        order.insert(order.end(), members.begin(), members.end());
    }
    return order;
}

// return the topological order of g with possibly cycles.
// XXX: related concept but this is not Bourdoncle's WTO
template <class G>
std::vector<typename G::node_t> weak_topo_sort(G g) {
    std::vector<typename G::node_t> sccg_order;
    scc_graph<G> scc_g(g, true /*preorder within scc*/);
    topo_sort(scc_g, sccg_order);
    std::vector<typename G::node_t> order;
    for (auto &n : sccg_order) {
        auto &members = scc_g.get_component_members(n);
        order.insert(order.end(), members.begin(), members.end());
    }
    return order;
}

} // end namespace graph_algo
} // end namespace analyzer
} // end namespace crab
