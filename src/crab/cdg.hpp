#pragma once 

#include "crab/dominance.hpp"

/*

  Node y is control-dependent on x if y does NOT post-dominate x but
  there exists a path from x to y such that all nodes in the path
  (different from x and y) are post-dominated by y.

 */
namespace crab {
  namespace analyzer {
   namespace graph_algo {

     // OUT: cdeps is a map from nodes to a set of nodes that
     // control-dependent on it.
     template <typename G, typename VectorMap>
     void control_dep_graph (G g, VectorMap &cdg) {
       VectorMap pdf;
       crab::analyzer::graph_algo::post_dominance (g, pdf);
       
       for (auto &kv: pdf) {
	 for (auto v: kv.second) {
	   auto &cdeps = cdg[v];
	   if (std::find(cdeps.begin (), cdeps.end (), kv.first) == cdeps.end ()) {
	     cdeps.push_back (kv.first);
	   }
	 }
       }
       
       CRAB_LOG("cdg",
		crab::outs () << "Control-dependence graph \n";
		for (auto &kv: cdg) {
		  crab::outs () << "{";
		  for (auto v: kv.second) {
		    crab::outs () << crab::cfg_impl::get_label_str(v) << ";";
		  }
		  crab::outs () << "} " << " control-dependent on ";
		  crab::outs () << crab::cfg_impl::get_label_str(kv.first) << "\n";
		});
     }
     
   } // end namespace
  } // end namespace
} // end namespace
