/*******************************************************************************
 *
 * Generic implementation of non-relational domains.
 *
 * Author: Arnaud J. Venet (arnaud.j.venet@nasa.gov)
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

#include "crab/patricia_trees.hpp"
#include "crab/types.hpp"

namespace crab {

template <typename Key, typename Value>
class separate_domain {

  private:
    using patricia_tree_t = patricia_tree<Key, Value>;
    using unary_op_t = typename patricia_tree_t::unary_op_t;
    using binary_op_t = typename patricia_tree_t::binary_op_t;
    using partial_order_t = typename patricia_tree_t::partial_order_t;

  public:
    using separate_domain_t = separate_domain<Key, Value>;
    using iterator = typename patricia_tree_t::iterator;
    using key_type = Key;
    using value_type = Value;

  private:
    bool _is_bottom;
    patricia_tree_t _tree;

  public:
    class join_op : public binary_op_t {
        std::pair<bool, std::optional<Value>> apply(Value x, Value y) {
            Value z = x.operator|(y);
            if (z.is_top()) {
                return {false, std::optional<Value>()};
            } else {
                return {false, std::optional<Value>(z)};
            }
        };

        bool default_is_absorbing() { return true; }
    }; // class join_op

    class widening_op : public binary_op_t {
        std::pair<bool, std::optional<Value>> apply(Value x, Value y) {
            Value z = x.widen(y);
            if (z.is_top()) {
                return {false, std::optional<Value>()};
            } else {
                return {false, std::optional<Value>(z)};
            }
        };

        bool default_is_absorbing() { return true; }

    }; // class widening_op

    template <typename Thresholds>
    class widening_thresholds_op : public binary_op_t {
        const Thresholds& m_ts;

      public:
        widening_thresholds_op(const Thresholds& ts) : m_ts(ts) {}

        std::pair<bool, std::optional<Value>> apply(Value x, Value y) {
            Value z = x.widening_thresholds(y, m_ts);
            if (z.is_top()) {
                return {false, std::optional<Value>()};
            } else {
                return {false, std::optional<Value>(z)};
            }
        };

        bool default_is_absorbing() { return true; }

    }; // class widening_thresholds_op

    class meet_op : public binary_op_t {
        std::pair<bool, std::optional<Value>> apply(Value x, Value y) {
            Value z = x.operator&(y);
            if (z.is_bottom()) {
                return {true, std::optional<Value>()};
            } else {
                return {false, std::optional<Value>(z)};
            }
        };

        bool default_is_absorbing() { return false; }

    }; // class meet_op

    class narrowing_op : public binary_op_t {
        std::pair<bool, std::optional<Value>> apply(Value x, Value y) {
            Value z = x.narrow(y);
            if (z.is_bottom()) {
                return {true, std::optional<Value>()};
            } else {
                return {false, std::optional<Value>(z)};
            }
        };

        bool default_is_absorbing() { return false; }

    }; // class narrowing_op

    class domain_po : public partial_order_t {
        bool leq(Value x, Value y) { return x.operator<=(y); }

        bool default_is_top() { return true; }

    }; // class domain_po

  public:
    static separate_domain_t top() { return separate_domain_t(); }

    static separate_domain_t bottom() { return separate_domain_t(false); }

  private:
    static patricia_tree_t apply_operation(binary_op_t& o, patricia_tree_t t1, patricia_tree_t t2, bool& is_bottom) {
        is_bottom = t1.merge_with(t2, o);
        return t1;
    }

    separate_domain(patricia_tree_t t) : _is_bottom(false), _tree(t) {}

    separate_domain(bool b) : _is_bottom(!b) {}

  public:
    separate_domain() : _is_bottom(false) {}

    separate_domain(const separate_domain_t& e) : _is_bottom(e._is_bottom), _tree(e._tree) {}

    separate_domain(const separate_domain_t&& e) : _is_bottom(e._is_bottom), _tree(std::move(e._tree)) {}

    separate_domain_t& operator=(separate_domain_t e) {
        this->_is_bottom = e._is_bottom;
        this->_tree = e._tree;
        return *this;
    }

    iterator begin() const {
        if (this->is_bottom()) {
            CRAB_ERROR("Separate domain: trying to invoke iterator on bottom");
        } else {
            return this->_tree.begin();
        }
    }

    iterator end() const {
        if (this->is_bottom()) {
            CRAB_ERROR("Separate domain: trying to invoke iterator on bottom");
        } else {
            return this->_tree.end();
        }
    }

    bool is_bottom() const { return this->_is_bottom; }

    bool is_top() const { return (!this->is_bottom() && this->_tree.size() == 0); }

    bool operator<=(separate_domain_t e) {
        if (this->is_bottom()) {
            return true;
        } else if (e.is_bottom()) {
            return false;
        } else {
            domain_po po;
            return this->_tree.leq(e._tree, po);
        }
    }

    bool operator==(separate_domain_t e) { return (this->operator<=(e) && e.operator<=(*this)); }

    // Join
    separate_domain_t operator|(separate_domain_t e) {
        if (this->is_bottom()) {
            return e;
        } else if (e.is_bottom()) {
            return *this;
        } else {
            join_op o;
            bool is_bottom;
            patricia_tree_t res = apply_operation(o, this->_tree, e._tree, is_bottom);
            return separate_domain_t(std::move(res));
        }
    }

    // Meet
    separate_domain_t operator&(separate_domain_t e) {
        if (this->is_bottom() || e.is_bottom()) {
            return this->bottom();
        } else {
            meet_op o;
            bool is_bottom;
            patricia_tree_t res = apply_operation(o, this->_tree, e._tree, is_bottom);
            if (is_bottom) {
                return this->bottom();
            } else {
                return separate_domain_t(std::move(res));
            }
        }
    }

    // Widening
    separate_domain_t widen(separate_domain_t e) {
        if (this->is_bottom()) {
            return e;
        } else if (e.is_bottom()) {
            return *this;
        } else {
            widening_op o;
            bool is_bottom;
            patricia_tree_t res = apply_operation(o, this->_tree, e._tree, is_bottom);
            return separate_domain_t(std::move(res));
        }
    }

    // Widening with thresholds
    template <typename Thresholds>
    separate_domain_t widening_thresholds(separate_domain_t e, const Thresholds& ts) {
        if (this->is_bottom()) {
            return e;
        } else if (e.is_bottom()) {
            return *this;
        } else {
            widening_thresholds_op<Thresholds> o(ts);
            bool is_bottom;
            patricia_tree_t res = apply_operation(o, this->_tree, e._tree, is_bottom);
            return separate_domain_t(std::move(res));
        }
    }

    // Narrowing
    separate_domain_t narrow(separate_domain_t e) {
        if (this->is_bottom() || e.is_bottom()) {
            return separate_domain_t(false);
        } else {
            narrowing_op o;
            bool is_bottom;
            patricia_tree_t res = apply_operation(o, this->_tree, e._tree, is_bottom);
            if (is_bottom) {
                return this->bottom();
            } else {
                return separate_domain_t(std::move(res));
            }
        }
    }

    void set(Key k, Value v) {
        if (!this->is_bottom()) {
            if (v.is_bottom()) {
                this->_is_bottom = true;
                this->_tree = patricia_tree_t();
            } else if (v.is_top()) {
                this->_tree.remove(k);
            } else {
                this->_tree.insert(k, v);
            }
        }
    }

    void set_to_bottom() {
        this->_is_bottom = true;
        this->_tree = patricia_tree_t();
    }

    separate_domain_t& operator-=(Key k) {
        if (!this->is_bottom()) {
            this->_tree.remove(k);
        }
        return *this;
    }

    Value operator[](Key k) const {
        if (this->is_bottom()) {
            return Value::bottom();
        } else {
            std::optional<Value> v = this->_tree.lookup(k);
            if (v) {
                return *v;
            } else {
                return Value::top();
            }
        }
    }

    std::size_t size() const {
        if (is_bottom()) {
            return 0;
        } else if (is_top()) {
            CRAB_ERROR("separate_domains::size() is undefined if top");
        } else {
            return this->_tree.size();
        }
    }

    void write(crab_os& o) const {
        if (this->is_bottom()) {
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

    friend crab_os& operator<<(crab_os& o, const separate_domain<Key, Value>& d) {
        d.write(o);
        return o;
    }
}; // class separate_domain

} // namespace crab
