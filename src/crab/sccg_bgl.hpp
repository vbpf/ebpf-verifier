#pragma once

/* Convert a Strongly connected component graph into BGL graph */

#include<boost/graph/graph_traits.hpp>
#include<boost/graph/graph_concepts.hpp>
#include<boost/graph/properties.hpp>

#include"crab/sccg.hpp"

namespace boost {

  template<class G>
  struct graph_traits<crab::analyzer::graph_algo::scc_graph<G>>  {

    typedef crab::analyzer::graph_algo::scc_graph<G> sccg_t;

    typedef typename sccg_t::node_t vertex_descriptor;
    typedef typename sccg_t::edge_t edge_descriptor;
    typedef typename sccg_t::node_iterator vertex_iterator;
    typedef typename sccg_t::pred_iterator in_edge_iterator;
    typedef typename sccg_t::succ_iterator out_edge_iterator;

    typedef disallow_parallel_edge_tag edge_parallel_category;
    typedef bidirectional_tag directed_category;
    struct  this_graph_tag : virtual bidirectional_graph_tag,
                             virtual vertex_list_graph_tag {};
    typedef this_graph_tag traversal_category;

    typedef size_t vertices_size_type;
    typedef size_t edges_size_type;
    typedef size_t degree_size_type;

    static vertex_descriptor null_vertex() {
      vertex_descriptor n;
      return n;
    }

  }; // end class graph_traits
}


// XXX: should be boost namespace but for some reason gcc does not
//      like it
namespace crab {
namespace analyzer {
namespace graph_algo {

// --- Functions for crab::analyzer::graph_algo::scc_graph<G>

template<class G>
typename boost::graph_traits<crab::analyzer::graph_algo::scc_graph<G>>::vertex_descriptor
source(typename
       boost::graph_traits<crab::analyzer::graph_algo::scc_graph<G>>::edge_descriptor e,
       const crab::analyzer::graph_algo::scc_graph<G> &g) {
  return e.Src();
 }

template<class G>
typename boost::graph_traits<crab::analyzer::graph_algo::scc_graph<G>>::vertex_descriptor
target(typename
       boost::graph_traits<crab::analyzer::graph_algo::scc_graph<G>>::edge_descriptor e,
       const crab::analyzer::graph_algo::scc_graph<G> &g) {
  return e.Dest();
}

template<class G>
std::pair<typename
	  boost::graph_traits<crab::analyzer::graph_algo::scc_graph<G>>::in_edge_iterator,
	  typename
	  boost::graph_traits<crab::analyzer::graph_algo::scc_graph<G>>::in_edge_iterator>
in_edges(typename
	 boost::graph_traits<crab::analyzer::graph_algo::scc_graph<G>>::vertex_descriptor v,
	 const crab::analyzer::graph_algo::scc_graph<G> &g) {
  return g.preds(v);
}

template<class G>
typename boost::graph_traits<crab::analyzer::graph_algo::scc_graph<G>>::degree_size_type
in_degree(typename
	  boost::graph_traits<crab::analyzer::graph_algo::scc_graph<G>>::vertex_descriptor v,
	  const crab::analyzer::graph_algo::scc_graph<G> &g) {
  return g.num_preds(v);
}

template<class G>
typename boost::graph_traits<crab::analyzer::graph_algo::scc_graph<G>>::degree_size_type
out_degree(typename
	   boost::graph_traits<crab::analyzer::graph_algo::scc_graph<G>>::vertex_descriptor v,
	   const crab::analyzer::graph_algo::scc_graph<G> &g) {
  return g.num_succs(v);
}

template<class G>
std::pair<typename
	  boost::graph_traits<crab::analyzer::graph_algo::scc_graph<G>>::out_edge_iterator,
	  typename
	  boost::graph_traits<crab::analyzer::graph_algo::scc_graph<G>>::out_edge_iterator>
out_edges(typename
	  boost::graph_traits<crab::analyzer::graph_algo::scc_graph<G>>::vertex_descriptor v,
	  const crab::analyzer::graph_algo::scc_graph<G> &g) {
  return g.succs(v);
}

template<class G>
typename boost::graph_traits<crab::analyzer::graph_algo::scc_graph<G>>::degree_size_type
degree(typename
       boost::graph_traits<crab::analyzer::graph_algo::scc_graph<G>>::vertex_descriptor v,
       const crab::analyzer::graph_algo::scc_graph<G> &g) {
  return g.num_preds(v) + g.num_succs(v);
}

template<class G>
std::pair<typename
	  boost::graph_traits<crab::analyzer::graph_algo::scc_graph<G>>::vertex_iterator,
	  typename
	  boost::graph_traits<crab::analyzer::graph_algo::scc_graph<G>>::vertex_iterator>
vertices(const crab::analyzer::graph_algo::scc_graph<G> &g) {
  return g.nodes();
}

template<class G>
typename boost::graph_traits<crab::analyzer::graph_algo::scc_graph<G>>::vertices_size_type
num_vertices(const crab::analyzer::graph_algo::scc_graph<G> &g) {
  return g.num_nodes();
}

}  // end namespace
} // end namespace
} // end namespace
