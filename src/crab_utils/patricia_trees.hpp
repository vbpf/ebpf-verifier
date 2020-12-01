// SPDX-License-Identifier: NASA-1.3
/*******************************************************************************
 *
 * Implementation of Patricia trees based on the algorithms described in
 * C. Okasaki and A. Gill's paper: "Fast Mergeable Integer Maps",
 * Workshop on ML, September 1998, pages 77-86.
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

#include <algorithm>
#include <memory>
#include <optional>
#include <vector>

#include <boost/iterator/iterator_facade.hpp>

namespace crab {

// Numerical type for indexed objects
using index_t = uint64_t;

inline index_t index(index_t i) { return i; }

template <typename T>
inline index_t index(const T& x) { return x.index(); }

namespace patricia_trees_impl {

inline index_t highest_bit(index_t x, index_t m) {
    index_t x_ = x & ~(m - 1);
    index_t m_ = m;

    while (x_ != m_) {
        x_ = x_ & ~m_;
        m_ = 2 * m_;
    }
    return m_;
}

inline index_t compute_branching_bit(index_t p0, index_t m0, index_t p1, index_t m1) {
    return highest_bit(p0 ^ p1, std::max((index_t)1, 2 * std::max(m0, m1)));
}

inline index_t mask(index_t k, index_t m) { return (k | (m - 1)) & ~m; }

inline bool zero_bit(index_t k, index_t m) { return (k & m) == 0; }

inline bool match_prefix(index_t k, index_t p, index_t m) { return mask(k, m) == p; }

template <typename Key, typename Value>
class tree {
  public:
    using tree_t = tree<Key, Value>;
    using tree_ptr = std::shared_ptr<tree_t>;

    class partial_order_t {
      public:
        virtual bool leq(Value, Value) = 0;
        // True if the default value is the top element for the partial order (false if it is bottom)
        virtual bool default_is_top() = 0;

        virtual ~partial_order_t() = default;

    }; // class partial_order

    class binary_action_t {
      public:
        // if first element of the pair is true then bottom and ignore second element
        // else if second element of the pair is empty then top
        // else the value stored in the second element of the pair.
        // The operation is idempotent: apply(x, x) = x
        virtual std::pair<bool, std::optional<Value>> apply(const Value&, const Value&) = 0;

        // True if the default value is absorbing (false if it is neutral)
        virtual bool default_is_absorbing() = 0;

        virtual ~binary_action_t() = default;

    }; // class binary_action

    using binding_t = std::pair<const Key&, const Value&>;

  public:
    static tree_ptr make_node(index_t, index_t, tree_ptr, tree_ptr);
    static tree_ptr make_leaf(const Key&, const Value&);
    static std::pair<bool, tree_ptr> merge(tree_ptr, tree_ptr, binary_action_t&, bool);
    static tree_ptr join(tree_ptr t0, tree_ptr t1);
    static std::pair<bool, tree_ptr> insert(tree_ptr, const Key&, const Value&, binary_action_t&, bool);
    static tree_ptr remove(tree_ptr, const Key&);
    static bool compare(tree_ptr, tree_ptr, partial_order_t&, bool);

  public:
    [[nodiscard]] virtual std::size_t size() const = 0;
    [[nodiscard]] virtual bool is_leaf() const = 0;
    virtual binding_t binding() const = 0;
    virtual tree_ptr left_branch() const = 0;
    virtual tree_ptr right_branch() const = 0;
    [[nodiscard]] virtual index_t prefix() const = 0;
    [[nodiscard]] virtual index_t branching_bit() const = 0;
    virtual std::optional<Value> lookup(const Key&) const = 0;

  public:
    [[nodiscard]] bool is_node() const { return !is_leaf(); }

    virtual ~tree() = default;

  public:
    class iterator : public boost::iterator_facade<iterator, binding_t, boost::forward_traversal_tag, binding_t> {
        friend class boost::iterator_core_access;

      private:
        using branching_t = std::pair<tree_ptr, int>;
        using branching_stack_t = std::vector<branching_t>;

      private:
        tree_ptr _current;
        branching_stack_t _stack;

      public:
        iterator() = default;

        explicit iterator(tree_ptr t) { this->look_for_next_leaf(t); }

      private:
        void look_for_next_leaf(tree_ptr t) {
            if (t) {
                if (t->is_leaf()) {
                    this->_current = t;
                } else {
                    branching_t b(t, 0);
                    this->_stack.push_back(b);
                    this->look_for_next_leaf(t->left_branch());
                }
            } else {
                if (!this->_stack.empty()) {
                    branching_t up;
                    do {
                        up = this->_stack.back();
                        this->_stack.pop_back();
                    } while (!this->_stack.empty() && up.second == 1);
                    if (!(this->_stack.empty() && up.second == 1)) {
                        branching_t b(up.first, 1);
                        this->_stack.push_back(b);
                        this->look_for_next_leaf(up.first->right_branch());
                    }
                }
            }
        }

        void increment() {
            if (this->_current) {
                this->_current.reset();
                if (!this->_stack.empty()) {
                    branching_t up;
                    do {
                        up = this->_stack.back();
                        this->_stack.pop_back();
                    } while (!this->_stack.empty() && up.second == 1);
                    if (!(this->_stack.empty() && up.second == 1)) {
                        this->look_for_next_leaf(up.first->right_branch());
                    }
                }
            } else {
                CRAB_ERROR("Patricia tree: trying to increment an empty iterator");
            }
        }

        bool equal(const iterator& it) const {
            if (this->_current != it._current) {
                return false;
            }
            if (this->_stack.size() != it._stack.size()) {
                return false;
            }
            typename branching_stack_t::const_iterator s_it1, s_it2;
            s_it1 = this->_stack.begin();
            s_it2 = it._stack.begin();
            while (s_it1 != this->_stack.end()) {
                if (*s_it1 != *s_it2) {
                    return false;
                }
                ++s_it1;
                ++s_it2;
            }
            return true;
        }

        binding_t dereference() const {
            if (this->_current) {
                return this->_current->binding();
            } else {
                CRAB_ERROR("Patricia tree: trying to dereference an empty iterator");
            }
        }

    }; // class iterator

}; // class tree

template <typename Key, typename Value>
class node final : public tree<Key, Value> {
  private:
    using tree_ptr = typename tree<Key, Value>::tree_ptr;
    using binding_t = typename tree<Key, Value>::binding_t;
    using node_t = node<Key, Value>;

  private:
    std::size_t _size;
    index_t _prefix;
    index_t _branching_bit;
    tree_ptr _left_branch;
    tree_ptr _right_branch;

  public:
    node() = delete;
    node(const node_t&) = delete;
    node_t& operator=(const node_t&) = delete;

  public:
    node(index_t prefix_, index_t branching_bit_, tree_ptr left_branch_, tree_ptr right_branch_)
        : _size(0), _prefix(prefix_), _branching_bit(branching_bit_), _left_branch(left_branch_),
          _right_branch(right_branch_) {
        if (left_branch_) {
            this->_size += left_branch_->size();
        }
        if (right_branch_) {
            this->_size += right_branch_->size();
        }
    }

    [[nodiscard]] std::size_t size() const { return this->_size; }

    [[nodiscard]] index_t prefix() const { return this->_prefix; }

    [[nodiscard]] index_t branching_bit() const { return this->_branching_bit; }

    [[nodiscard]] bool is_leaf() const { return false; }

    binding_t binding() const { CRAB_ERROR("Patricia tree: trying to call binding() on a node"); }

    tree_ptr left_branch() const { return this->_left_branch; }

    tree_ptr right_branch() const { return this->_right_branch; }

    std::optional<Value> lookup(const Key& key) const {
        if (index(key) <= this->_prefix) {
            if (this->_left_branch) {
                return this->_left_branch->lookup(key);
            } else {
                return std::optional<Value>();
            }
        } else {
            if (this->_right_branch) {
                return this->_right_branch->lookup(key);
            } else {
                return std::optional<Value>();
            }
        }
    }

}; // class node

template <typename Key, typename Value>
class leaf final : public tree<Key, Value> {
  private:
    using tree_ptr = typename tree<Key, Value>::tree_ptr;
    using binding_t = typename tree<Key, Value>::binding_t;
    using leaf_t = leaf<Key, Value>;

  private:
    Key _key;
    Value _value;

  public:
    leaf() = delete;
    leaf(const leaf_t&) = delete;
    leaf_t& operator=(const leaf_t&) = delete;

  public:
    leaf(const Key& key_, const Value& value_) : _key(key_), _value(value_) {}

    [[nodiscard]] std::size_t size() const { return 1; }

    [[nodiscard]] index_t prefix() const { return index(this->_key); }

    [[nodiscard]] index_t branching_bit() const { return 0; }

    [[nodiscard]] bool is_leaf() const { return true; }

    binding_t binding() const { return binding_t(this->_key, this->_value); }

    tree_ptr left_branch() const { CRAB_ERROR("Patricia tree: trying to call left_branch() on a leaf"); }

    tree_ptr right_branch() const { CRAB_ERROR("Patricia tree: trying to call right_branch() on a leaf"); }

    std::optional<Value> lookup(const Key& key_) const {
        if (index(this->_key) == index(key_)) {
            return std::optional<Value>(this->_value);
        } else {
            return std::optional<Value>();
        }
    }

}; // class leaf

template <typename Key, typename Value>
auto tree<Key, Value>::make_node(index_t prefix, index_t branching_bit, tree_ptr left_branch, tree_ptr right_branch) -> tree_ptr {
    if (left_branch) {
        if (right_branch) {
            return
                typename tree<Key, Value>::tree_ptr(new node<Key, Value>(prefix, branching_bit, left_branch, right_branch));
        } else {
            return left_branch;
        }
    } else {
        if (right_branch) {
            return right_branch;
        } else {
            return {}; // both branches are empty
        }
    }
}

template <typename Key, typename Value>
auto tree<Key, Value>::make_leaf(const Key& key, const Value& value) -> tree_ptr {
    return typename tree<Key, Value>::tree_ptr(new leaf<Key, Value>(key, value));
}

template <typename Key, typename Value>
auto tree<Key, Value>::join(tree_ptr t0, tree_ptr t1) -> tree_ptr {
    index_t p0 = t0->prefix();
    index_t p1 = t1->prefix();
    index_t m = compute_branching_bit(p0, t0->branching_bit(), p1, t1->branching_bit());
    tree_ptr t;

    if (zero_bit(p0, m)) {
        t = make_node(mask(p0, m), m, t0, t1);
    } else {
        t = make_node(mask(p0, m), m, t1, t0);
    }
    return t;
}

template <typename Key, typename Value>
auto tree<Key, Value>::insert(tree_ptr t, const Key& key_, const Value& value_, binary_action_t& op,
                              bool combine_left_to_right) -> std::pair<bool, tree_ptr> {
    tree_ptr nil;
    std::pair<bool, tree_ptr> res_lb, res_rb;
    std::pair<bool, std::optional<Value>> new_value;
    std::pair<bool, tree_ptr> bottom = {true, nil};
    if (t) {
        if (t->is_node()) {
            index_t branching_bit = t->branching_bit();
            index_t prefix = t->prefix();
            if (match_prefix(index(key_), prefix, branching_bit)) {
                if (zero_bit(index(key_), branching_bit)) {
                    tree_ptr lb = t->left_branch();
                    tree_ptr new_lb;
                    if (lb) {
                        auto [is_bottom, tree_ptr] = insert(lb, key_, value_, op, combine_left_to_right);
                        if (is_bottom) {
                            return bottom;
                        }
                        new_lb = tree_ptr;
                    } else {
                        if (!op.default_is_absorbing()) {
                            new_lb = make_leaf(key_, value_);
                        }
                    }
                    if (new_lb == lb) {
                        return {false, t};
                    } else {
                        return {false, make_node(prefix, branching_bit, new_lb, t->right_branch())};
                    }
                } else {
                    tree_ptr rb = t->right_branch();
                    tree_ptr new_rb;
                    if (rb) {
                        auto [is_bottom, tree_ptr] = insert(rb, key_, value_, op, combine_left_to_right);
                        if (is_bottom) {
                            return bottom;
                        }
                        new_rb = tree_ptr;
                    } else {
                        if (!op.default_is_absorbing()) {
                            new_rb = make_leaf(key_, value_);
                        }
                    }
                    if (new_rb == rb) {
                        return {false, t};
                    } else {
                        return {false, make_node(prefix, branching_bit, t->left_branch(), new_rb)};
                    }
                }
            } else {
                if (op.default_is_absorbing()) {
                    return {false, t};
                } else {
                    return {false, join(make_leaf(key_, value_), t)};
                }
            }
        } else {
            const auto& [key, value] = t->binding();
            if (index(key) == index(key_)) {
                new_value = combine_left_to_right ? op.apply(value, value_) : op.apply(value_, value);
                if (new_value.first) {
                    return bottom;
                }
                if (new_value.second) {
                    if (*(new_value.second) == value) {
                        return {false, t};
                    } else {
                        return {false, make_leaf(key_, *(new_value.second))};
                    }
                } else {
                    return {false, nil};
                }
            } else {
                if (op.default_is_absorbing()) {
                    return {false, t};
                } else {
                    return {false, join(make_leaf(key_, value_), t)};
                }
            }
        }
    } else {
        if (op.default_is_absorbing()) {
            return {false, nil};
        } else {
            return {false, make_leaf(key_, value_)};
        }
    }
}

template <typename Key, typename Value>
auto tree<Key, Value>::remove(tree_ptr t, const Key& key_) -> tree_ptr {
    tree_ptr nil;
    index_t id = index(key_);
    if (t) {
        if (t->is_node()) {
            index_t branching_bit = t->branching_bit();
            index_t prefix = t->prefix();
            if (match_prefix(id, prefix, branching_bit)) {
                if (zero_bit(id, branching_bit)) {
                    tree_ptr lb = t->left_branch();
                    tree_ptr new_lb;
                    if (lb) {
                        new_lb = remove(lb, key_);
                    }
                    if (new_lb == lb) {
                        return t;
                    } else {
                        return make_node(prefix, branching_bit, new_lb, t->right_branch());
                    }
                } else {
                    tree_ptr rb = t->right_branch();
                    tree_ptr new_rb;
                    if (rb) {
                        new_rb = remove(rb, key_);
                    }
                    if (new_rb == rb) {
                        return t;
                    } else {
                        return make_node(prefix, branching_bit, t->left_branch(), new_rb);
                    }
                }
            } else {
                return t;
            }
        } else {
            binding_t b = t->binding();
            if (index(b.first) == id) {
                return nil;
            } else {
                return t;
            }
        }
    } else {
        return nil;
    }
}

template <typename Key, typename Value>
auto tree<Key, Value>::merge(tree_ptr s, tree_ptr t, binary_action_t& op,
                             bool combine_left_to_right) -> std::pair<bool, tree_ptr> {
    constexpr tree_ptr nil;
    constexpr std::pair<bool, tree_ptr> bottom = {true, nil};
    if (s) {
        if (t) {
            if (s == t) {
                return {false, s};
            } else if (s->is_leaf()) {
                auto& [key, old_value] = s->binding();
                if (op.default_is_absorbing()) {
                    if (std::optional<Value> value = t->lookup(key, old_value)) {
                        auto [is_bottom, tree] = combine_left_to_right ? op.apply(old_value, *value) : op.apply(*value, old_value);
                        if (is_bottom) {
                            return bottom;
                        }
                        if (tree) {
                            if (*tree == old_value) {
                                return {false, s};
                            } else {
                                return {false, make_leaf(key, *value)};
                            }
                        } else {
                            return {false, nil};
                        }
                    } else {
                        return {false, nil};
                    }
                } else {
                    return insert(t, key, old_value, op, !combine_left_to_right);
                }
            } else if (t->is_leaf()) {
                auto& [key, old_value] = t->binding();
                if (op.default_is_absorbing()) {
                    if (std::optional<Value> value = s->lookup(key)) {
                        auto [is_bottom, new_value] = combine_left_to_right ? op.apply(*value, old_value) : op.apply(old_value, *value);
                        if (is_bottom) {
                            return bottom;
                        }
                        if (new_value) {
                            if (*new_value == old_value) {
                                return {false, t};
                            } else {
                                return {false, make_leaf(old_value, *new_value)};
                            }
                        } else {
                            return {false, nil};
                        }
                    } else {
                        return {false, nil};
                    }
                } else {
                    return insert(s, key, old_value, op, combine_left_to_right);
                }
            } else {
                if (s->branching_bit() == t->branching_bit() && s->prefix() == t->prefix()) {
                    auto [is_bottom_lb, new_lb] = merge(s->left_branch(), t->left_branch(), op, combine_left_to_right);
                    if (is_bottom_lb) {
                        return bottom;
                    }
                    auto [is_bottom_rb, new_rb] = merge(s->right_branch(), t->right_branch(), op, combine_left_to_right);
                    if (is_bottom_rb) {
                        return bottom;
                    }
                    if (new_lb == s->left_branch() && new_rb == s->right_branch()) {
                        return {false, s};
                    } else if (new_lb == t->left_branch() && new_rb == t->right_branch()) {
                        return {false, t};
                    } else {
                        return {false, make_node(s->prefix(), s->branching_bit(), new_lb, new_rb)};
                    }
                } else if (s->branching_bit() > t->branching_bit() &&
                           match_prefix(t->prefix(), s->prefix(), s->branching_bit())) {
                    if (zero_bit(t->prefix(), s->branching_bit())) {
                        auto [is_bottom, new_lb] = merge(s->left_branch(), t, op, combine_left_to_right);
                        if (is_bottom) {
                            return bottom;
                        }
                        tree_ptr new_rb = op.default_is_absorbing() ? nil : s->right_branch();
                        if (new_lb == s->left_branch() && new_rb == s->right_branch()) {
                            return {false, s};
                        } else {
                            return {false, make_node(s->prefix(), s->branching_bit(), new_lb, new_rb)};
                        }
                    } else {
                        tree_ptr new_lb = op.default_is_absorbing() ? nil : s->left_branch();
                        auto [is_bottom, new_rb] = merge(s->right_branch(), t, op, combine_left_to_right);
                        if (is_bottom) {
                            return bottom;
                        }
                        if (new_lb == s->left_branch() && new_rb == s->right_branch()) {
                            return {false, s};
                        } else {
                            return {false, make_node(s->prefix(), s->branching_bit(), new_lb, new_rb)};
                        }
                    }
                } else if (s->branching_bit() < t->branching_bit() &&
                           match_prefix(s->prefix(), t->prefix(), t->branching_bit())) {
                    if (zero_bit(s->prefix(), t->branching_bit())) {
                        auto [is_bottom, new_lb] = merge(s, t->left_branch(), op, combine_left_to_right);
                        if (is_bottom) {
                            return bottom;
                        }
                        tree_ptr new_rb = op.default_is_absorbing() ? nil : t->right_branch();
                        if (new_lb == t->left_branch() && new_rb == t->right_branch()) {
                            return {false, t};
                        } else {
                            return {false, make_node(t->prefix(), t->branching_bit(), new_lb, new_rb)};
                        }
                    } else {
                        tree_ptr new_lb = op.default_is_absorbing() ? nil : t->left_branch();
                        auto [is_bottom, new_rb] = merge(s, t->right_branch(), op, combine_left_to_right);
                        if (is_bottom) {
                            return bottom;
                        }
                        if (new_lb == t->left_branch() && new_rb == t->right_branch()) {
                            return {false, t};
                        } else {
                            return {false, make_node(t->prefix(), t->branching_bit(), new_lb, new_rb)};
                        }
                    }
                } else {
                    if (op.default_is_absorbing()) {
                        return {false, nil};
                    } else {
                        return {false, join(s, t)};
                    }
                }
            }
        } else {
            if (op.default_is_absorbing()) {
                return {false, nil};
            } else {
                return {false, s};
            }
        }
    } else {
        if (op.default_is_absorbing()) {
            return {false, nil};
        } else {
            return {false, t};
        }
    }
}

template <typename Key, typename Value>
bool tree<Key, Value>::compare(tree_ptr s, tree_ptr t, partial_order_t& po,
                               bool compare_left_to_right) {
    if (s) {
        if (t) {
            if (s != t) {
                if (s->is_leaf()) {
                    auto [key, value] = s->binding();
                    std::optional<Value> value_ = t->lookup(key);
                    if (value_) {
                        Value left = compare_left_to_right ? value : *value_;
                        Value right = compare_left_to_right ? *value_ : value;
                        if (!po.leq(left, right)) {
                            return false;
                        }
                    } else {
                        if ((compare_left_to_right && !po.default_is_top()) ||
                            (!compare_left_to_right && po.default_is_top())) {
                            return false;
                        }
                    }
                    if (compare_left_to_right && po.default_is_top() && !t->is_leaf()) {
                        return false;
                    }
                    if (!compare_left_to_right && !po.default_is_top() && !t->is_leaf()) {
                        return false;
                    }
                } else if (t->is_leaf()) {
                    if (!compare(t, s, po, !compare_left_to_right)) {
                        return false;
                    }
                } else {
                    if (s->branching_bit() == t->branching_bit() && s->prefix() == t->prefix()) {
                        if (!compare(s->left_branch(), t->left_branch(), po, compare_left_to_right)) {
                            return false;
                        }
                        if (!compare(s->right_branch(), t->right_branch(), po, compare_left_to_right)) {
                            return false;
                        }
                    } else if (s->branching_bit() > t->branching_bit() &&
                               match_prefix(t->prefix(), s->prefix(), s->branching_bit())) {
                        if ((compare_left_to_right && !po.default_is_top()) ||
                            (!compare_left_to_right && po.default_is_top())) {
                            return false;
                        }
                        if (zero_bit(t->prefix(), s->branching_bit())) {
                            if (!compare(s->left_branch(), t, po, compare_left_to_right)) {
                                return false;
                            }
                        } else {
                            if (!compare(s->right_branch(), t, po, compare_left_to_right)) {
                                return false;
                            }
                        }
                    } else if (s->branching_bit() < t->branching_bit() &&
                               match_prefix(s->prefix(), t->prefix(), t->branching_bit())) {
                        if ((compare_left_to_right && po.default_is_top()) ||
                            (!compare_left_to_right && !po.default_is_top())) {
                            return false;
                        }
                        if (zero_bit(s->prefix(), t->branching_bit())) {
                            if (!compare(s, t->left_branch(), po, compare_left_to_right)) {
                                return false;
                            }
                        } else {
                            if (!compare(s, t->right_branch(), po, compare_left_to_right)) {
                                return false;
                            }
                        }
                    } else {
                        return false;
                    }
                }
            }
        } else {
            if ((compare_left_to_right && !po.default_is_top()) || (!compare_left_to_right && po.default_is_top())) {
                return false;
            }
        }
    } else {
        if (t) {
            if ((compare_left_to_right && po.default_is_top()) || (!compare_left_to_right && !po.default_is_top())) {
                return false;
            }
        } else {
            // s and t are empty
        }
    }
    return true;
}

} // namespace patricia_trees_impl

template <typename Key, typename Value>
class patricia_tree final {
  private:
    using tree_t = patricia_trees_impl::tree<Key, Value>;
    using tree_ptr = typename tree_t::tree_ptr;

  public:
    using patricia_tree_t = patricia_tree<Key, Value>;
    using binary_action_t = typename tree_t::binary_action_t;
    using partial_order_t = typename tree_t::partial_order_t;
    using binding_t = typename tree_t::binding_t;

  private:
    tree_ptr _tree;

  public:
    class iterator : public boost::iterator_facade<iterator, binding_t, boost::forward_traversal_tag, binding_t> {
        friend class boost::iterator_core_access;
        friend class patricia_tree<Key, Value>;

      private:
        typename tree_t::iterator _it;

      public:
        iterator() = default;

        explicit iterator(const patricia_tree_t& pt) : _it(pt._tree) {}

      private:
        explicit iterator(tree_ptr t) : _it(t) {}

        void increment() { ++this->_it; }

        bool equal(const iterator& other) const { return this->_it == other._it; }

        binding_t dereference() const { return *this->_it; }

    }; // class iterator

    class insert_op : public binary_action_t {
        std::pair<bool, std::optional<Value>> apply(const Value& /* old_value */, const Value& new_value) {
            return {false, std::optional<Value>(new_value)};
        }
        bool default_is_absorbing() { return false; }
    }; // class insert_op

  public:
    patricia_tree() = default;

    patricia_tree(const patricia_tree_t& t) : _tree(t._tree) {}

    patricia_tree& operator=(const patricia_tree_t& t) {
        this->_tree = t._tree;
        return *this;
    }

    [[nodiscard]] std::size_t size() const {
        if (this->_tree) {
            return this->_tree->size();
        } else {
            return 0;
        }
    }

    iterator begin() const { return iterator(this->_tree); }

    iterator end() const { return iterator(); }

    std::optional<Value> lookup(const Key& key) const {
        if (this->_tree) {
            return this->_tree->lookup(key);
        } else {
            return std::optional<Value>();
        }
    }

    bool merge_with(const patricia_tree_t& t, binary_action_t& op) {
        auto [is_bottom, tree_ptr] = tree_t::merge(this->_tree, t._tree, op, true);
        if (is_bottom) {
            return true; // bottom must be propagated
        } else {
            this->_tree = tree_ptr;
            return false;
        }
    }

    void insert(const Key& key, const Value& value) {
        insert_op op;
        auto [is_bottom, tree_ptr] = tree_t::insert(this->_tree, key, value, op, true);
        this->_tree = tree_ptr;
    }

    void remove(const Key& key) { this->_tree = tree_t::remove(this->_tree, key); }

    void clear() { this->_tree.reset(); }

    [[nodiscard]] bool empty() const { return !this->_tree; }

    bool leq(const patricia_tree_t& t, partial_order_t& po) const {
        return tree_t::compare(this->_tree, t._tree, po, true);
    }

}; // class patricia_tree

} // namespace crab
