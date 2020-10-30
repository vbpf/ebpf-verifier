/*******************************************************************************
 *
 * Construction and management of weak topological orderings (WTOs).
 *
 * The construction of weak topological orderings is based on F. Bourdoncle's
 * paper: "Efficient chaotic iteration strategies with widenings", Formal
 * Methods in Programming and Their Applications, 1993, pages 128-141.
 *
 * Author: Arnaud J. Venet (arnaud.j.venet@nasa.gov)
 * Contributors: Jorge A. Navas (jorge.navas@sri.com)
 *
 * Notices:
 *
 * Copyright (c) 2011 United States Government as represented by the
 * Administrator of the National Aeronautics and Space Administration.
 * All Rights Reserved.
 *
 * Disclaimers:
 *
 * No Warranty: THE SUBJECT SOFTWARE IS PROVIDED "AS IS" WITHOUT ANY WARRANTY OF
 * ANY KIND, EITHER EXPRESSED, IMPLIED, OR STATUTORY, INCLUDING, BUT NOT LIMITED
 * TO, ANY WARRANTY THAT THE SUBJECT SOFTWARE WILL CONFORM TO SPECIFICATIONS,
 * ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE,
 * OR FREEDOM FROM INFRINGEMENT, ANY WARRANTY THAT THE SUBJECT SOFTWARE WILL BE
 * ERROR FREE, OR ANY WARRANTY THAT DOCUMENTATION, IF PROVIDED, WILL CONFORM TO
 * THE SUBJECT SOFTWARE. THIS AGREEMENT DOES NOT, IN ANY MANNER, CONSTITUTE AN
 * ENDORSEMENT BY GOVERNMENT AGENCY OR ANY PRIOR RECIPIENT OF ANY RESULTS,
 * RESULTING DESIGNS, HARDWARE, SOFTWARE PRODUCTS OR ANY OTHER APPLICATIONS
 * RESULTING FROM USE OF THE SUBJECT SOFTWARE.  FURTHER, GOVERNMENT AGENCY
 * DISCLAIMS ALL WARRANTIES AND LIABILITIES REGARDING THIRD-PARTY SOFTWARE,
 * IF PRESENT IN THE ORIGINAL SOFTWARE, AND DISTRIBUTES IT "AS IS."
 *
 * Waiver and Indemnity:  RECIPIENT AGREES TO WAIVE ANY AND ALL CLAIMS AGAINST
 * THE UNITED STATES GOVERNMENT, ITS CONTRACTORS AND SUBCONTRACTORS, AS WELL
 * AS ANY PRIOR RECIPIENT.  IF RECIPIENT'S USE OF THE SUBJECT SOFTWARE RESULTS
 * IN ANY LIABILITIES, DEMANDS, DAMAGES, EXPENSES OR LOSSES ARISING FROM SUCH
 * USE, INCLUDING ANY DAMAGES FROM PRODUCTS BASED ON, OR RESULTING FROM,
 * RECIPIENT'S USE OF THE SUBJECT SOFTWARE, RECIPIENT SHALL INDEMNIFY AND HOLD
 * HARMLESS THE UNITED STATES GOVERNMENT, ITS CONTRACTORS AND SUBCONTRACTORS,
 * AS WELL AS ANY PRIOR RECIPIENT, TO THE EXTENT PERMITTED BY LAW.
 * RECIPIENT'S SOLE REMEDY FOR ANY SUCH MATTER SHALL BE THE IMMEDIATE,
 * UNILATERAL TERMINATION OF THIS AGREEMENT.
 *
 ******************************************************************************/

#pragma once

#include <memory>
#include <set>
#include <vector>
#include <forward_list>
#include <unordered_map>
#include <variant>

#include "crab/cfg_bgl.hpp"
#include "crab/debug.hpp"
#include "crab/interval.hpp"
#include "crab/stats.hpp"
#include "crab/types.hpp"


namespace crab {


using vertex_descriptor_t = typename boost::graph_traits<cfg_t>::vertex_descriptor;


using out_edge_iterator_t = typename boost::graph_traits<cfg_t>::out_edge_iterator;


using edge_descriptor_t = typename boost::graph_traits<cfg_t>::edge_descriptor;


class wto_t;
class wto_vertex_t;
class wto_cycle_t;


class wto_nesting_t final {

    friend class wto_t;
    friend class wto_vertex_t;
    friend class wto_cycle_t;

  private:
    using node_list_t = std::vector<vertex_descriptor_t>;
    using node_list_ptr = std::shared_ptr<node_list_t>;

    node_list_ptr _nodes;

  public:
    using iterator = typename node_list_t::iterator;
    using const_iterator = typename node_list_t::const_iterator;

  private:
    explicit wto_nesting_t(const node_list_ptr& l) : _nodes(std::make_shared<node_list_t>(*l)) {}

    int compare(wto_nesting_t& other) const {
        auto this_it = this->begin();
        auto other_it = other.begin();
        while (this_it != this->end()) {
            if (other_it == other.end()) {
                return 1;
            } else if (*this_it == *other_it) {
                ++this_it;
                ++other_it;
            } else {
                return 2; // Nestings are not comparable
            }
        }
        if (other_it == other.end()) {
            return 0;
        } else {
            return -1;
        }
    }

  public:
    wto_nesting_t() : _nodes(std::make_shared<node_list_t>()) {}

    void operator+=(const vertex_descriptor_t& n) {
        this->_nodes = std::make_shared<node_list_t>(*(this->_nodes));
        this->_nodes->push_back(n);
    }

    wto_nesting_t operator+(const vertex_descriptor_t& n) {
        wto_nesting_t res(this->_nodes);
        res._nodes->push_back(n);
        return res;
    }

    iterator begin() { return _nodes->begin(); }

    iterator end() { return _nodes->end(); }

    const_iterator begin() const { return _nodes->begin(); }

    const_iterator end() const { return _nodes->end(); }

    wto_nesting_t operator^(wto_nesting_t other) const {
        wto_nesting_t res;
        for (const_iterator this_it = this->begin(), other_it = other.begin();
             this_it != this->end() && other_it != other.end(); ++this_it, ++other_it) {
            if (*this_it == *other_it) {
                res._nodes->push_back(*this_it);
            } else {
                break;
            }
        }
        return res;
    }

    bool operator<=(wto_nesting_t other) const { return this->compare(other) <= 0; }

    bool operator==(wto_nesting_t other) const { return this->compare(other) == 0; }

    bool operator>(wto_nesting_t other) const { return this->compare(other) == 1; }

    friend std::ostream& operator<<(std::ostream& o, const wto_nesting_t& k) {
        o << "[";
        for (auto it = k.begin(); it != k.end();) {
            vertex_descriptor_t n = *it;
            o << n;
            ++it;
            if (it != k.end()) {
                o << ", ";
            }
        }
        o << "]";
        return o;
    }
}; // class nesting

using wto_component_t = std::variant<wto_vertex_t, wto_cycle_t>;
std::ostream& operator<<(std::ostream& o, const wto_component_t& c);

class wto_vertex_t final {

    friend class wto_t;

  private:
    vertex_descriptor_t _node;

    explicit wto_vertex_t(vertex_descriptor_t node) : _node(std::move(node)) {}

  public:
    vertex_descriptor_t node() { return this->_node; }

    friend std::ostream& operator<<(std::ostream& o, const wto_vertex_t& vertex);

}; // class wto_vertex


class wto_cycle_t final {

    friend class wto_t;
  private:
    using wto_component_list_t = std::forward_list<wto_component_t>;

    vertex_descriptor_t _head;
    wto_component_list_t _wto_components;
    // number of times the wto cycle is analyzed by the fixpoint iterator
    unsigned _num_fixpo;

    wto_cycle_t(vertex_descriptor_t head, const wto_component_list_t& wto_components)
        : _head(head), _wto_components(wto_components), _num_fixpo(0) {}

  public:
    using iterator = wto_component_list_t::iterator;
    using const_iterator = wto_component_list_t::const_iterator;

    vertex_descriptor_t head() { return this->_head; }

    iterator begin() { return _wto_components.begin(); }

    iterator end() { return _wto_components.end(); }

    const_iterator begin() const { return _wto_components.begin(); }

    const_iterator end() const { return _wto_components.end(); }

    void increment_fixpo_visits() { _num_fixpo++; }

    friend std::ostream& operator<<(std::ostream& o, const wto_cycle_t& cycle) {
        o << "(" << cycle._head;
        if (!cycle._wto_components.empty()) {
            o << " ";
            for (const wto_component_t& c : cycle) {
                o << c << " ";
            }
        }
        o << ")";
        if (cycle._num_fixpo > 0)
            o << "^{" << cycle._num_fixpo << "}";
        return o;
    }

}; // class wto_cycle

inline std::ostream& operator<<(std::ostream& o, const wto_vertex_t& vertex) {
    return o << vertex._node;
}

inline std::ostream& operator<<(std::ostream& o, const wto_component_t& c) {
    return std::visit(overloaded{
        [&](const wto_cycle_t& x) -> std::ostream& { return o << x; },
        [&](const wto_vertex_t& x) -> std::ostream& { return o << x; },
    }, c);
}

class wto_t final {
  private:
    using wto_component_list_t = std::forward_list<wto_component_t>;
    using dfn_t = bound_t;
    using dfn_table_t = std::unordered_map<vertex_descriptor_t, dfn_t>;
    using stack_t = std::vector<vertex_descriptor_t>;
    using nesting_table_t = std::unordered_map<vertex_descriptor_t, wto_nesting_t>;

    wto_component_list_t _wto_components;
    dfn_table_t _dfn_table;
    dfn_t _num{0};
    stack_t _stack;
    nesting_table_t _nesting_table;

    class nesting_builder {
      private:
        wto_nesting_t _nesting;
        nesting_table_t& _nesting_table;

      public:
        explicit nesting_builder(nesting_table_t& nesting_table) : _nesting_table(nesting_table) {}

        void operator()(wto_cycle_t& cycle) {
            vertex_descriptor_t head = cycle.head();
            wto_nesting_t previous_nesting = this->_nesting;
            this->_nesting_table.insert(std::make_pair(head, this->_nesting));
            this->_nesting += head;
            for (wto_component_t& c : cycle) {
                std::visit(*this, c);
            }
            this->_nesting = previous_nesting;
        }

        void operator()(wto_vertex_t& vertex) {
            this->_nesting_table.insert(std::make_pair(vertex.node(), this->_nesting));
        }

    }; // class nesting_builder

    dfn_t get_dfn(const vertex_descriptor_t& n) {
        auto it = this->_dfn_table.find(n);
        if (it == this->_dfn_table.end()) {
            return 0;
        } else {
            return it->second;
        }
    }

    void set_dfn(const vertex_descriptor_t& n, const dfn_t& dfn) {
        std::pair<typename dfn_table_t::iterator, bool> res = this->_dfn_table.insert(std::make_pair(n, dfn));
        if (!res.second) {
            (res.first)->second = dfn;
        }
    }

    vertex_descriptor_t pop() {
        if (this->_stack.empty()) {
            CRAB_ERROR("WTO computation: empty stack");
        } else {
            vertex_descriptor_t top = this->_stack.back();
            this->_stack.pop_back();
            return top;
        }
    }

    void push(const vertex_descriptor_t& n) { this->_stack.push_back(n); }

    wto_component_t component(cfg_t& g, const vertex_descriptor_t& vertex) {
        wto_component_list_t partition;
        std::pair<out_edge_iterator_t, out_edge_iterator_t> succ_edges = out_edges(vertex, g);
        for (out_edge_iterator_t it = succ_edges.first, et = succ_edges.second; it != et; ++it) {
            vertex_descriptor_t succ = target(*it, g);
            if (this->get_dfn(succ) == 0) {
                this->operator()(g, succ, partition);
            }
        }
        return wto_cycle_t(vertex, partition);
    }

    struct visit_stack_elem {
        using succ_iterator = out_edge_iterator_t;
        vertex_descriptor_t _node;
        succ_iterator _it; // begin iterator for node's successors
        succ_iterator _et; // end iterator for node's successors
        dfn_t _min;        // smallest dfn number of any (direct or
        // indirect) node's successor through node's
        // DFS subtree, included node.

        visit_stack_elem(vertex_descriptor_t node, const std::pair<succ_iterator, succ_iterator>& succs, const dfn_t& min)
            : _node(std::move(node)), _it(succs.first), _et(succs.second), _min(min) {}
    };

    void operator()(cfg_t& g, const vertex_descriptor_t& vertex, wto_component_list_t& partition) {

        std::vector<visit_stack_elem> visit_stack;
        std::set<vertex_descriptor_t> loop_nodes;

        /* discover vertex */
        push(vertex);
        _num += 1;
        set_dfn(vertex, _num);

        visit_stack.emplace_back(vertex, out_edges(vertex, g), _num);
        CRAB_LOG("wto-nonrec", std::cout << "WTO: Node " << vertex << ": dfs num=" << _num << "\n";);
        while (!visit_stack.empty()) {
            /*
             * Perform dfs.
             *
             * When this loop terminates, visit_stack.back()_node's children
             * have been processed.  For each loop iteration we push in
             * visit_stack one more descendant.
             */
            while (visit_stack.back()._it != visit_stack.back()._et) {
                edge_descriptor_t e = *visit_stack.back()._it++;
                vertex_descriptor_t child = target(e, g);
                dfn_t child_dfn = get_dfn(child);
                if (child_dfn == 0) {
                    /* discover new vertex */
                    push(child);
                    _num += 1;
                    set_dfn(child, _num);
                    visit_stack.emplace_back(child, out_edges(child, g), _num);
                    CRAB_LOG("wto-nonrec", std::cout << "WTO: Node " << child << ": dfs num=" << _num << "\n";);
                } else {
                    if (child_dfn <= visit_stack.back()._min) {
                        visit_stack.back()._min = child_dfn;
                        CRAB_LOG("wto-nonrec", std::cout << "WTO: loop found " << child << "\n";);
                        loop_nodes.insert(child);
                    }
                }
            }

            // propagate min from child to parent
            vertex_descriptor_t visiting_node = visit_stack.back()._node;
            dfn_t min_visiting_node = visit_stack.back()._min;
            bool is_loop = loop_nodes.count(visiting_node) > 0;
            visit_stack.pop_back();
            if (!visit_stack.empty() && visit_stack.back()._min > min_visiting_node) {
                visit_stack.back()._min = min_visiting_node;
            }

            auto dfn_visiting_node = get_dfn(visiting_node);
            CRAB_LOG("wto-nonrec", std::cout << "WTO: popped node " << visiting_node << " dfs num= "
                                             << dfn_visiting_node << ": min=" << min_visiting_node << "\n";);

            if (min_visiting_node == get_dfn(visiting_node)) {
                CRAB_LOG("wto-nonrec",
                         std::cout << "WTO: BEGIN building partition for node " << visiting_node << "\n";);
                set_dfn(visiting_node, dfn_t::plus_infinity());
                vertex_descriptor_t element = pop();
                if (is_loop) {
                    while (!(element == visiting_node)) {
                        set_dfn(element, 0);
                        CRAB_LOG("wto-nonrec", std::cout << "\tWTO: node " << element << ": dfn num=0\n";);
                        element = pop();
                    }
                    CRAB_LOG("wto-nonrec",
                             std::cout << "\tWTO: adding component starting from " << visiting_node << "\n";);
                    partition.push_front(component(g, visiting_node));
                } else {
                    CRAB_LOG("wto-nonrec", std::cout << "\tWTO: adding vertex " << visiting_node << "\n";);
                    partition.push_front(wto_vertex_t(visiting_node));
                }
                CRAB_LOG("wto-nonrec", std::cout << "WTO: END building partition\n";);
            }
        } // end while (!visit_stack.empty())
    }

    void build_nesting() {
        nesting_builder builder(this->_nesting_table);
        for (wto_component_t& c : *this) {
            std::visit(builder, c);
        }
    }

  public:
    using iterator = wto_component_list_t::iterator;
    using const_iterator = wto_component_list_t::const_iterator;

    explicit wto_t(cfg_t& g) {
        ScopedCrabStats __st__("Fixpo.WTO");

        this->operator()(g, entry(g), this->_wto_components);
        this->build_nesting();
    }

    wto_t(const wto_t& other) = delete;

    wto_t(wto_t&& other) = default;

    wto_t& operator=(const wto_t& other) = default;

    iterator begin() { return _wto_components.begin(); }

    iterator end() { return _wto_components.end(); }

    const_iterator begin() const { return _wto_components.begin(); }

    const_iterator end() const { return _wto_components.end(); }

    wto_nesting_t nesting(vertex_descriptor_t n) {
        auto it = this->_nesting_table.find(n);
        if (it == this->_nesting_table.end()) {
            CRAB_ERROR("WTO nesting: node ", n, " not found");
        } else {
            return it->second;
        }
    }

    friend std::ostream& operator<<(std::ostream& o, const wto_t& wto) {
        for (const wto_component_t& c : wto) {
            o << c << " ";
        }
        return o;
    }
}; // class wto

} // namespace crab
