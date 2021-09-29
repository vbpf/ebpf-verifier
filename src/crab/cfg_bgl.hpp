// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

/*
 * Convert a CFG into a BGL (Boost Graph Library) graph
 */
#include <boost/graph/graph_traits.hpp>
#include <boost/graph/properties.hpp>
#include <boost/iterator/transform_iterator.hpp>

#include "crab/cfg.hpp"

namespace crab {

namespace graph {
template <typename G>
struct mk_in_edge {
    using Node = typename boost::graph_traits<G>::vertex_descriptor;
    using Edge = typename boost::graph_traits<G>::edge_descriptor;

    Node _dst;
    mk_in_edge() {}
    mk_in_edge(const Node& dst) : _dst(dst) {}
    Edge operator()(const Node& src) const { return Edge(src, _dst); }
};

template <typename G>
struct mk_out_edge {
    using Node = typename boost::graph_traits<G>::vertex_descriptor;
    using Edge = typename boost::graph_traits<G>::edge_descriptor;

    Node _src;
    mk_out_edge() {}
    mk_out_edge(const Node& src) : _src(src) {}
    Edge operator()(const Node& dst) const { return Edge(_src, dst); }
};
} // end namespace graph
} // end namespace crab

namespace boost {

// cfg
template <>
struct graph_traits<crab::cfg_t> {
    using graph_t = crab::cfg_t;
    using vertex_descriptor = crab::label_t;
    using edge_descriptor = std::pair<vertex_descriptor, vertex_descriptor>;
    using const_edge_descriptor = std::pair<const vertex_descriptor, const vertex_descriptor>;

    using edge_parallel_category = disallow_parallel_edge_tag;
    using directed_category = bidirectional_tag;
    struct this_graph_tag : virtual bidirectional_graph_tag, virtual vertex_list_graph_tag {};
    using traversal_category = this_graph_tag;

    using vertices_size_type = size_t;
    using edges_size_type = size_t;
    using degree_size_type = size_t;

    // iterator of label_t's
    using vertex_iterator = typename graph_t::label_iterator;
    // iterator of pairs of label_t's
    using in_edge_iterator = transform_iterator<crab::graph::mk_in_edge<graph_t>, typename graph_t::neighbour_iterator>;
    // iterator of pairs of label_t's
    using out_edge_iterator = transform_iterator<crab::graph::mk_out_edge<graph_t>, typename graph_t::neighbour_iterator>;
}; // end class graph_traits

// cfg_rev
template <>
struct graph_traits<crab::cfg_rev_t> {
    using graph_t = crab::cfg_rev_t;
    using vertex_descriptor = crab::label_t;
    using edge_descriptor = std::pair<vertex_descriptor, vertex_descriptor>;
    using const_edge_descriptor = std::pair<const vertex_descriptor, const vertex_descriptor>;

    using edge_parallel_category = disallow_parallel_edge_tag;
    using directed_category = bidirectional_tag;
    struct this_graph_tag : virtual bidirectional_graph_tag, virtual vertex_list_graph_tag {};
    using traversal_category = this_graph_tag;

    using vertices_size_type = size_t;
    using edges_size_type = size_t;
    using degree_size_type = size_t;

    using vertex_iterator = typename graph_t::label_iterator;
    using in_edge_iterator =
        boost::transform_iterator<crab::graph::mk_in_edge<graph_t>, typename graph_t::neighbour_iterator>;
    using out_edge_iterator =
        boost::transform_iterator<crab::graph::mk_out_edge<graph_t>, typename graph_t::neighbour_iterator>;
}; // end class graph_traits
} // namespace boost

// XXX: do not put it in the boost namespace because it won't compile
namespace crab {

// cfg

//// boost/graph/graph_traits.hpp has already default source/target
//// functions in case the edge_descriptor is std::pair.

// this is not part of BGL but needed by Crab's algorithms
inline typename boost::graph_traits<cfg_t>::vertex_descriptor entry(const cfg_t& g) { return g.entry_label(); }

inline std::pair<typename boost::graph_traits<cfg_t>::vertex_iterator,
                 typename boost::graph_traits<cfg_t>::vertex_iterator>
vertices(cfg_t& g) {
    return std::make_pair(g.label_begin(), g.label_end());
}

inline std::pair<typename boost::graph_traits<cfg_t>::out_edge_iterator,
                 typename boost::graph_traits<cfg_t>::out_edge_iterator>
out_edges(typename boost::graph_traits<cfg_t>::vertex_descriptor v, cfg_t& g) {
    auto& node = g.get_node(v);
    auto p = node.next_blocks();
    return std::make_pair(boost::make_transform_iterator(p.first, graph::mk_out_edge<cfg_t>(v)),
                          boost::make_transform_iterator(p.second, graph::mk_out_edge<cfg_t>(v)));
}

inline std::pair<typename boost::graph_traits<cfg_t>::in_edge_iterator,
                 typename boost::graph_traits<cfg_t>::in_edge_iterator>
in_edges(typename boost::graph_traits<cfg_t>::vertex_descriptor v, cfg_t& g) {
    auto& node = g.get_node(v);
    auto p = node.prev_blocks();
    return std::make_pair(boost::make_transform_iterator(p.first, graph::mk_in_edge<cfg_t>(v)),
                          boost::make_transform_iterator(p.second, graph::mk_in_edge<cfg_t>(v)));
}

inline typename boost::graph_traits<cfg_t>::vertices_size_type num_vertices(cfg_t& g) {
    return std::distance(g.label_begin(), g.label_end());
}

inline typename boost::graph_traits<cfg_t>::degree_size_type
in_degree(typename boost::graph_traits<cfg_t>::vertex_descriptor v, const cfg_t& g) {
    auto preds = g.prev_nodes(v);
    return std::distance(preds.begin(), preds.end());
}

inline typename boost::graph_traits<cfg_t>::degree_size_type
out_degree(typename boost::graph_traits<cfg_t>::vertex_descriptor v, const cfg_t& g) {
    auto succs = g.next_nodes(v);
    return std::distance(succs.begin(), succs.end());
}

inline typename boost::graph_traits<cfg_t>::degree_size_type
degree(typename boost::graph_traits<cfg_t>::vertex_descriptor v, const cfg_t& g) {
    return out_degree(v, g) + in_degree(v, g);
}

// cfg_rev

//// boost/graph/graph_traits.hpp has already default source/target
//// functions in case the edge_descriptor is std::pair.

// this is not part of BGL but needed by Crab's algorithms
inline typename boost::graph_traits<cfg_rev_t>::vertex_descriptor entry(const cfg_rev_t& g) { return g.entry_label(); }

inline std::pair<typename boost::graph_traits<cfg_rev_t>::vertex_iterator,
                 typename boost::graph_traits<cfg_rev_t>::vertex_iterator>
vertices(cfg_rev_t g) {
    return std::make_pair(g.label_begin(), g.label_end());
}

inline std::pair<typename boost::graph_traits<cfg_rev_t>::out_edge_iterator,
                 typename boost::graph_traits<cfg_rev_t>::out_edge_iterator>
out_edges(typename boost::graph_traits<cfg_rev_t>::vertex_descriptor v, cfg_rev_t g) {
    auto& node = g.get_node(v);
    auto p = node.next_blocks();
    return std::make_pair(boost::make_transform_iterator(p.first, graph::mk_out_edge<cfg_rev_t>(v)),
                          boost::make_transform_iterator(p.second, graph::mk_out_edge<cfg_rev_t>(v)));
}

inline std::pair<typename boost::graph_traits<cfg_rev_t>::in_edge_iterator,
                 typename boost::graph_traits<cfg_rev_t>::in_edge_iterator>
in_edges(typename boost::graph_traits<cfg_rev_t>::vertex_descriptor v, cfg_rev_t g) {
    auto& node = g.get_node(v);
    auto p = node.prev_blocks();
    return std::make_pair(boost::make_transform_iterator(p.first, graph::mk_in_edge<cfg_rev_t>(v)),
                          boost::make_transform_iterator(p.second, graph::mk_in_edge<cfg_rev_t>(v)));
}

inline typename boost::graph_traits<cfg_rev_t>::vertices_size_type num_vertices(cfg_rev_t g) {
    return std::distance(g.label_begin(), g.label_end());
}

inline typename boost::graph_traits<cfg_rev_t>::degree_size_type
in_degree(typename boost::graph_traits<cfg_rev_t>::vertex_descriptor v, cfg_rev_t g) {
    auto preds = g.prev_nodes(v);
    return std::distance(preds.begin(), preds.end());
}

inline typename boost::graph_traits<cfg_rev_t>::degree_size_type
out_degree(typename boost::graph_traits<cfg_rev_t>::vertex_descriptor v, cfg_rev_t g) {
    auto succs = g.next_nodes(v);
    return std::distance(succs.begin(), succs.end());
}

inline typename boost::graph_traits<cfg_rev_t>::degree_size_type
degree(typename boost::graph_traits<cfg_rev_t>::vertex_descriptor v, cfg_rev_t g) {
    return out_degree(v, g) + in_degree(v, g);
}

} // namespace crab
