#pragma once

#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/graph_traits.hpp>
#include <boost/graph/strong_components.hpp>
#include <boost/iterator/transform_iterator.hpp>
#include <boost/make_shared.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/unordered_map.hpp>
#include <memory>

#include "crab/debug.hpp"
#include "crab/types.hpp"

/*
   Strongly connected component graph
 */

namespace crab {
namespace analyzer {
namespace graph_algo {

template <typename G>
class scc_graph {

  public:
    using node_t = typename G::node_t;

  private:
    /// --- begin internal representation of the scc_graph
    struct vertex_t {
        std::size_t m_comp;
        node_t m_repr;
    };
    using scc_graph_t =
        boost::adjacency_list<boost::setS, // disallow parallel edges
                              boost::vecS, boost::bidirectionalS,
                              boost::property<boost::vertex_color_t, boost::default_color_type, vertex_t>>;
    using scc_graph_ptr = std::shared_ptr<scc_graph_t>;
    using vertex_descriptor_t = typename boost::graph_traits<scc_graph_t>::vertex_descriptor;
    using edge_descriptor_t = typename boost::graph_traits<scc_graph_t>::edge_descriptor;
    using vertex_iterator = typename boost::graph_traits<scc_graph_t>::vertex_iterator;
    using out_edge_iterator = typename boost::graph_traits<scc_graph_t>::out_edge_iterator;
    using in_edge_iterator = typename boost::graph_traits<scc_graph_t>::in_edge_iterator;
    /// --- end internal representation of the scc_graph

    using component_map_t = boost::unordered_map<node_t, std::size_t>;
    using comp_to_vertex_map_t = boost::unordered_map<std::size_t, vertex_descriptor_t>;
    using comp_members_map_t = boost::unordered_map<std::size_t, std::vector<node_t>>;

    // Wrapper for edges
    // XXX: BGL complains if we use std::pair<edge_t,edge_t>
    template <typename T>
    struct Edge {
        T m_s;
        T m_d;
        Edge() {}
        Edge(T s, T d) : m_s(s), m_d(d) {}
        T Src() const { return m_s; }
        T Dest() const { return m_d; }
        bool operator==(const Edge<T> &o) const { return (m_s == o.Src() && m_d == o.Dest()); }
        bool operator!=(const Edge<T> &o) const { return !(*this == o); }
    };
    // input graph
    G m_g;
    // if true all members in the same SCC are sorted in
    // pre-order, otherwise post-order.
    bool m_same_scc_order;
    // output dag
    scc_graph_ptr m_sccg;
    // map each m_g node to a SCC id
    component_map_t m_comp_map;
    // map each SCC id to an internal m_sccg's node id
    comp_to_vertex_map_t m_comp_to_vertex_map;
    // map each SCC id to a vector of m_g's nodes (its members)
    comp_members_map_t m_comp_members_map;

  public:
    using edge_t = Edge<node_t>;

  private:
    struct MkNode : public std::unary_function<vertex_descriptor_t, node_t> {

        scc_graph_t *_g;

        MkNode() : _g(nullptr) {}
        MkNode(scc_graph_t *g) : _g(g) {}
        node_t &operator()(const vertex_descriptor_t &v) const { return (*_g)[v].m_repr; }
    };

    struct MkEdge : public std::unary_function<edge_descriptor_t, Edge<node_t>> {

        scc_graph_t *_g;

        MkEdge() : _g(nullptr) {}
        MkEdge(scc_graph_t *g) : _g(g) {}
        Edge<node_t> operator()(const edge_descriptor_t &e) const {
            node_t &s = (*_g)[boost::source(e, *_g)].m_repr;
            node_t &t = (*_g)[boost::target(e, *_g)].m_repr;
            return Edge<node_t>(s, t);
        }
    };

    std::size_t get_comp_id(const node_t &n) const {
        auto it = m_comp_map.find(n);
        assert(it != m_comp_map.end());
        return it->second;
    }

    struct preorder_visitor : public boost::default_dfs_visitor {
        std::vector<node_t> m_order_vs;
        void discover_vertex(node_t v, G g) { m_order_vs.push_back(v); }
    };

    struct postorder_visitor : public boost::default_dfs_visitor {
        std::vector<node_t> m_order_vs;
        void finish_vertex(node_t v, G g) { m_order_vs.push_back(v); }
    };

    template <typename OrderVis>
    std::vector<node_t> sort() const {
        using color_map_t = boost::unordered_map<node_t, boost::default_color_type>;
        color_map_t color;
        for (auto v : boost::make_iterator_range(vertices(m_g))) {
            color[v] = boost::default_color_type();
        }
        boost::associative_property_map<color_map_t> cm(color);

        // find root
        node_t root;
        bool root_found = false;
        for (auto v : boost::make_iterator_range(vertices(m_g))) {
            if (in_degree(v, m_g) == 0) {
                root = v;
                root_found = true;
                break;
            }
        }

        OrderVis vis;
        if (root_found)
            boost::detail::depth_first_visit_impl(m_g, root, vis, cm, boost::detail::nontruth2());

        for (auto u : boost::make_iterator_range(vertices(m_g))) {
            if (get(cm, u) == boost::default_color_type::white_color)
                boost::detail::depth_first_visit_impl(m_g, u, vis, cm, boost::detail::nontruth2());
        }

        assert(vis.m_order_vs.size() == num_vertices(m_g));

        return vis.m_order_vs;
    }

    bool check_comp_map() {
        // --- Check that all vertices in the graph m_g are keys in
        //     the component map
        for (auto v : boost::make_iterator_range(vertices(m_g))) {
            auto it = m_comp_map.find(v);
            if (it == m_comp_map.end())
                return false;
        }
        return true;
    }

  public:
    using node_iterator = boost::transform_iterator<MkNode, vertex_iterator>;
    using pred_iterator = boost::transform_iterator<MkEdge, in_edge_iterator>;
    using succ_iterator = boost::transform_iterator<MkEdge, out_edge_iterator>;

    scc_graph(G g, bool order = false /*default post-order*/)
        : m_g(g), m_same_scc_order(order), m_sccg(std::make_shared<scc_graph_t>()) {

        CRAB_LOG("sccg", crab::outs() << g << "\n");

        using root_map_t = boost::unordered_map<node_t, node_t>;
        using color_map_t = boost::unordered_map<node_t, boost::default_color_type>;
        using property_component_map_t = boost::associative_property_map<component_map_t>;
        using property_root_map_t = boost::associative_property_map<root_map_t>;
        using property_color_map_t = boost::associative_property_map<color_map_t>;

        component_map_t discover_time;
        root_map_t _root_map;
        color_map_t color_map;

        for (auto const &v : boost::make_iterator_range(vertices(m_g))) {
            m_comp_map[v] = 0;
            color_map[v] = boost::default_color_type();
            discover_time[v] = 0;
            _root_map[v] = node_t();
        }

        boost::strong_components(m_g, property_component_map_t(m_comp_map),
                                 root_map(property_root_map_t(_root_map))
                                     .color_map(property_color_map_t(color_map))
                                     .discover_time_map(property_component_map_t(discover_time)));

        CRAB_LOG("sccg", crab::outs() << "comp map: \n";
                 for (auto p
                      : m_comp_map) { crab::outs() << "\t" << p.first << " --> " << p.second << "\n"; });

        // build SCC Dag

        for (auto p : m_comp_map) {
            auto it = m_comp_to_vertex_map.find(p.second);
            if (it != m_comp_to_vertex_map.end())
                continue;
            vertex_descriptor_t v = add_vertex(*m_sccg);
            (*m_sccg)[v].m_comp = p.second;
            m_comp_to_vertex_map.insert(std::make_pair(p.second, v));
            CRAB_LOG("sccg", crab::outs() << "Added scc graph node " << p.second << "--- id=" << v << "\n";);
        }

        for (const node_t &u : boost::make_iterator_range(vertices(m_g))) {
            for (auto e : boost::make_iterator_range(out_edges(u, m_g))) {
                const node_t &d = target(e, m_g);

                if (m_comp_map[u] == m_comp_map[d])
                    continue;

                auto res = add_edge(m_comp_to_vertex_map[m_comp_map[u]], m_comp_to_vertex_map[m_comp_map[d]], *m_sccg);

                if (res.second)
                    CRAB_LOG("sccg", crab::outs() << "Added scc graph edge " << m_comp_map[u] << " --> "
                                                  << m_comp_map[d] << "\n");
            }
        }

        assert(check_comp_map());

        // Build a map from scc id to their node members
        for (auto v : (m_same_scc_order ? sort<preorder_visitor>() : sort<postorder_visitor>())) {
            std::size_t id = m_comp_map[v];
            auto it = m_comp_members_map.find(id);
            if (it != m_comp_members_map.end()) {
                it->second.push_back(v);
            } else {
                std::vector<node_t> comp_mems;
                comp_mems.push_back(v);
                m_comp_members_map.insert(std::make_pair(id, comp_mems));
                // update the representative in m_sccg
                //
                // The representative is similar to the values in the
                // root_map's entries. However, we found cases where two members
                // of the same SCC have assigned a different root. I
                // think this contradicts to what the BOOST doc says but
                // I didn't have time to figure out the problem so we
                // choose our own representative.
                (*m_sccg)[m_comp_to_vertex_map[id]].m_repr = v;
            }
        }
        CRAB_LOG("sccg", crab::outs() << "Built SCC graph \n"; write(crab::outs()););
    }

    // return the members of the scc component that contains n
    std::vector<node_t> &get_component_members(const node_t &n) { return m_comp_members_map[m_comp_map[n]]; }

    std::pair<node_iterator, node_iterator> nodes() const {
        auto p = boost::vertices(*m_sccg);
        return std::make_pair(make_transform_iterator(p.first, MkNode(&*m_sccg)),
                              make_transform_iterator(p.second, MkNode(&*m_sccg)));
    }

    std::pair<succ_iterator, succ_iterator> succs(const node_t &n) const {
        auto It = m_comp_to_vertex_map.find(get_comp_id(n));
        if (It == m_comp_to_vertex_map.end())
            CRAB_ERROR("Sccg could not find node!");

        auto p = boost::out_edges(It->second, *m_sccg);
        return std::make_pair(make_transform_iterator(p.first, MkEdge(&*m_sccg)),
                              make_transform_iterator(p.second, MkEdge(&*m_sccg)));
    }

    std::pair<pred_iterator, pred_iterator> preds(const node_t &n) const {
        auto It = m_comp_to_vertex_map.find(get_comp_id(n));
        if (It == m_comp_to_vertex_map.end())
            CRAB_ERROR("Sccg could not find node!");

        auto p = boost::in_edges(It->second, *m_sccg);
        return std::make_pair(make_transform_iterator(p.first, MkEdge(&*m_sccg)),
                              make_transform_iterator(p.second, MkEdge(&*m_sccg)));
    }

    std::size_t num_nodes() const { return boost::num_vertices(*m_sccg); }

    std::size_t num_succs(const node_t &n) const {
        auto It = m_comp_to_vertex_map.find(get_comp_id(n));
        if (It == m_comp_to_vertex_map.end())
            CRAB_ERROR("Sccg could not find node!");

        return boost::out_degree(It->second, *m_sccg);
    }

    std::size_t num_preds(const node_t &n) const {
        auto It = m_comp_to_vertex_map.find(get_comp_id(n));
        if (It == m_comp_to_vertex_map.end())
            CRAB_ERROR("Sccg could not find node!");

        return boost::in_degree(It->second, *m_sccg);
    }

    void write(crab_os &o) const {
        o << "SCCG=\nvertices={";
        for (auto v : boost::make_iterator_range(nodes()))
            o << v << ";";
        o << "}\n";

        o << "edges=\n";
        for (auto v : boost::make_iterator_range(nodes())) {
            if (num_succs(v) > 0) {
                for (auto e : boost::make_iterator_range(succs(v))) {
                    o << e.Src() << "--> " << e.Dest() << "\n";
                }
            }
        }

        CRAB_LOG("sccg", o << "Component map: \n";
                 for (auto p
                      : m_comp_map) { o << "\t" << p.first << " --> SCC ID " << p.second << "\n"; });
    }
};

} // end namespace graph_algo
} // end namespace analyzer
} // end namespace crab
