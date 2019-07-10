#pragma once

/**
 * Specialized domains for kill-gen problems.
 **/

#include "crab/debug.hpp"
#include "crab/discrete_domains.hpp"
#include "crab/patricia_trees.hpp"
#include "crab/stats.hpp"

#include <boost/optional.hpp>

namespace crab {
namespace domains {

// A wrapper for discrete_domain (i.e,. set of Element)
template <class Element>
class flat_killgen_domain {

  private:
    typedef flat_killgen_domain<Element> flat_killgen_domain_t;
    typedef ikos::discrete_domain<Element> discrete_domain_t;

  public:
    typedef typename discrete_domain_t::iterator iterator;
    typedef Element element_t;

  private:
    discrete_domain_t _inv;

  public:
    flat_killgen_domain(discrete_domain_t inv) : _inv(inv) {}

    static flat_killgen_domain_t top() { return flat_killgen_domain(discrete_domain_t::top()); }

    static flat_killgen_domain_t bottom() { return flat_killgen_domain(discrete_domain_t::bottom()); }

    flat_killgen_domain() : _inv(discrete_domain_t::bottom()) {}

    flat_killgen_domain(Element e) : _inv(e) {}

    flat_killgen_domain(const flat_killgen_domain_t &o) : _inv(o._inv) {}

    flat_killgen_domain(flat_killgen_domain_t &&o) : _inv(std::move(o._inv)) {}

    flat_killgen_domain_t &operator=(const flat_killgen_domain_t &other) {
        if (this != &other)
            _inv = other._inv;
        return *this;
    }

    flat_killgen_domain_t &operator=(flat_killgen_domain_t &&other) {
        _inv = std::move(other._inv);
        return *this;
    }

    iterator begin() { return _inv.begin(); }

    iterator end() { return _inv.end(); }

    unsigned size() { return _inv.size(); }

    bool is_bottom() { return _inv.is_bottom(); }

    bool is_top() { return _inv.is_top(); }

    bool operator==(flat_killgen_domain_t other) { return *this <= other && other <= *this; }

    bool operator<=(flat_killgen_domain_t other) {
        if (is_bottom())
            return true;
        else if (other.is_top())
            return true;
        else
            return (_inv <= other._inv);
    }

    void operator-=(Element x) {
        if (is_bottom())
            return;
        _inv -= x;
    }

    void operator-=(flat_killgen_domain_t other) {
        if (is_bottom() || other.is_bottom())
            return;

        if (!other._inv.is_top()) {
            for (auto v : other)
                _inv -= v;
        }
    }

    void operator+=(Element x) {
        if (is_top())
            return;
        _inv += x;
    }

    void operator+=(flat_killgen_domain_t other) {
        if (is_top() || other.is_bottom()) {
            return;
        } else if (other.is_top()) {
            _inv = discrete_domain_t::top();
        } else {
            _inv = (_inv | other._inv);
        }
    }

    flat_killgen_domain_t operator|(flat_killgen_domain_t other) { return (_inv | other._inv); }

    flat_killgen_domain_t operator&(flat_killgen_domain_t other) { return (_inv & other._inv); }

    void write(crab_os &o) const { _inv.write(o); }
};

template <typename Elem>
inline crab_os &operator<<(crab_os &o, const flat_killgen_domain<Elem> &d) {
    d.write(o);
    return o;
}

// To represent sets of pairs (Key,Value).
// Bottom means empty set rather than failure.
template <typename Key, typename Value>
class separate_killgen_domain {

  private:
    typedef ikos::patricia_tree<Key, Value> patricia_tree_t;
    typedef typename patricia_tree_t::unary_op_t unary_op_t;
    typedef typename patricia_tree_t::binary_op_t binary_op_t;
    typedef typename patricia_tree_t::partial_order_t partial_order_t;

  public:
    typedef separate_killgen_domain<Key, Value> separate_killgen_domain_t;
    typedef typename patricia_tree_t::iterator iterator;
    typedef Key key_type;
    typedef Value value_type;

  private:
    bool _is_top;
    patricia_tree_t _tree;

    static patricia_tree_t apply_operation(binary_op_t &o, patricia_tree_t t1, patricia_tree_t t2, bool &is_bottom) {
        is_bottom = t1.merge_with(t2, o);
        return t1;
    }

    separate_killgen_domain(patricia_tree_t t) : _is_top(false), _tree(t) {}

    separate_killgen_domain(bool b) : _is_top(b) {}

    class join_op : public binary_op_t {
        std::pair<bool, boost::optional<Value>> apply(Value x, Value y) {
            Value z = x.operator|(y);
            if (z.is_top()) {
                return {false, boost::optional<Value>()};
            } else {
                return {false, boost::optional<Value>(z)};
            }
        }
        bool default_is_absorbing() { return false; }
    }; // class join_op

    class meet_op : public binary_op_t {
        boost::optional<Value> apply(Value x, Value y) {
            Value z = x.operator&(y);
            if (z.is_bottom()) {
                return {true, boost::optional<Value>()};
            } else {
                return {false, boost::optional<Value>(z)};
            }
        };
        bool default_is_absorbing() { return true; }
    }; // class meet_op

    class domain_po : public partial_order_t {
        bool leq(Value x, Value y) { return x.operator<=(y); }
        bool default_is_top() { return false; }
    }; // class domain_po

  public:
    static separate_killgen_domain_t top() { return separate_killgen_domain_t(true); }

    static separate_killgen_domain_t bottom() { return separate_killgen_domain_t(false); }

    separate_killgen_domain() : _is_top(false), _tree(patricia_tree_t()) {}

    separate_killgen_domain(const separate_killgen_domain_t &o) : _is_top(o._is_top), _tree(o._tree) {}

    separate_killgen_domain_t &operator=(separate_killgen_domain_t o) {
        this->_is_top = o._is_top;
        this->_tree = o._tree;
        return *this;
    }

    iterator begin() const {
        if (this->is_top()) {
            CRAB_ERROR("Separate killgen domain: trying to invoke iterator on top");
        } else {
            return this->_tree.begin();
        }
    }

    iterator end() const {
        if (this->is_top()) {
            CRAB_ERROR("Separate killgen domain: trying to invoke iterator on top");
        } else {
            return this->_tree.end();
        }
    }

    bool is_top() const { return _is_top; }

    bool is_bottom() const { return (!is_top() && _tree.empty()); }

    bool operator<=(separate_killgen_domain_t o) {
        domain_po po;
        return (o.is_top() || (!is_top() && (_tree.leq(o._tree, po))));
    }

    separate_killgen_domain_t operator|(separate_killgen_domain_t o) {
        if (is_top() || o.is_top()) {
            return separate_killgen_domain_t::top();
        } else {
            join_op op;
            bool is_bottom;
            patricia_tree_t res = apply_operation(op, _tree, o._tree, is_bottom);
            return separate_killgen_domain_t(std::move(res));
        }
    }

    separate_killgen_domain_t operator&(separate_killgen_domain_t o) {
        if (is_top()) {
            return o;
        } else if (o.is_top()) {
            return *this;
        } else {
            meet_op op;
            bool is_bottom;
            patricia_tree_t res = apply_operation(op, _tree, o._tree, is_bottom);
            if (is_bottom) {
                return separate_killgen_domain_t::bottom();
            } else {
                return separate_killgen_domain_t(std::move(res));
            }
        }
    }

    void set(Key k, Value v) {
        if (!is_top()) {
            // if (v.is_bottom()) {
            //   this->_tree.remove(k);
            // } else {
            //   this->_tree.insert(k, v);
            // }
            this->_tree.insert(k, v);
        }
    }

    separate_killgen_domain_t &operator-=(Key k) {
        if (!is_top()) {
            _tree.remove(k);
        }
        return *this;
    }

    Value operator[](Key k) {
        if (is_top())
            return Value::top();
        else {
            boost::optional<Value> v = _tree.lookup(k);
            if (v) {
                return *v;
            } else {
                return Value::bottom();
            }
        }
    }

    void write(crab::crab_os &o) const {
        if (this->is_top()) {
            o << "{...}";
        }
        if (_tree.empty()) {
            o << "_|_";
        } else {
            o << "{";
            for (typename patricia_tree_t::iterator it = this->_tree.begin(); it != this->_tree.end();) {
                Key k = it->first;
                k.write(o);
                o << " -> ";
                Value v = it->second;
                v.write(o);
                ++it;
                if (it != this->_tree.end()) {
                    o << "; ";
                }
            }
            o << "}";
        }
    }
}; // class separate_killgen_domain

template <typename Key, typename Value>
inline crab_os &operator<<(crab_os &o, const separate_killgen_domain<Key, Value> &d) {
    d.write(o);
    return o;
}

} // end namespace domains
} // end namespace crab
