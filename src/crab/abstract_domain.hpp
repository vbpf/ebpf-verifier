#pragma once

#include <vector>

#include "crab/abstract_domain_operators.hpp"
#include "crab/thresholds.hpp"

namespace crab {

namespace domains {

/**
 * All abstract domains must derive from the abstract_domain class
 * and expose publicly all its public typedef's.
 *
 * This is a sample of how to implement a new abstract domain:
 *
 * template<typename Number, typename VariableName>
 * class my_new_domain final: public abstract_domain<my_new_domain<Number,VariableName>> {
 *   ...
 *   bool is_bottom() {...}
 *   bool is_top() {...}
 *   ...
 * };
 *
 *
 * };
 **/

template <class Dom>
class abstract_domain : public writeable {
  public:
    using variable_vector_t = std::vector<variable_t>;

    abstract_domain() : writeable() {}

    virtual ~abstract_domain(){};

    static Dom top() {
        Dom abs;
        abs.set_to_top();
        return abs;
    }

    static Dom bottom() {
        Dom abs;
        abs.set_to_bottom();
        return abs;
    }

    /**************************** Lattice operations ****************************/

    // set *this to top
    virtual void set_to_top() = 0;
    // set *this to bottom
    virtual void set_to_bottom() = 0;
    // return true if the abstract state is bottom
    virtual bool is_bottom() = 0;
    // return true if the abstract state is top
    virtual bool is_top() = 0;

    // Inclusion operator: return true if *this is equal or more precise than abs
    // TODO: add const reference
    virtual bool operator<=(const Dom& abs) = 0;
    // Join operator: join(*this, abs)
    // TODO: add const reference and ideally const method
    virtual Dom operator|(const Dom& abs) = 0;
    // *this = join(*this, abs)
    // TODO: add const reference
    virtual void operator|=(const Dom& abs) = 0;
    // Meet operator: meet(*this, abs)
    // TODO: add const reference and ideally const method
    virtual Dom operator&(const Dom& abs) = 0;
    // Widening operator: widening(*this, abs)
    // TODO: add const reference and ideally const method
    virtual Dom widen(const Dom& abs) = 0;
    // Narrowing operator: narrowing(*this, abs)
    // TODO: add const reference and ideally const method
    virtual Dom narrow(const Dom& abs) = 0;
    // Widening with thresholds: widening_ts(*this, abs)
    virtual Dom widening_thresholds(Dom abs, const iterators::thresholds_t& ts) = 0;

    /**************************** Backward arithmetic operations ******************/
    // x = y op z
    // Substitute x with y op z in the abstract value
    // The result is meet with invariant.
    virtual void backward_apply(operation_t op, variable_t x, variable_t y, variable_t z, Dom invariant) = 0;
    // x = y op k
    // Substitute x with y op k in the abstract value
    // The result is meet with invariant.
    virtual void backward_apply(operation_t op, variable_t x, variable_t y, number_t k, Dom invariant) = 0;
    // x = e
    // Substitute x with e in the abstract value
    // The result is meet with invariant.
    virtual void backward_assign(variable_t x, linear_expression_t e, Dom invariant) = 0;

    /**************************** Miscellaneous operations *************************/
    // forget v
    virtual void operator-=(variable_t v) = 0;

    // Convert the abstract state into a conjunction of linear constraints
    virtual linear_constraint_system_t to_linear_constraint_system() = 0;

    // Rename in the abstract state the variables "from" with those from "to".
    virtual void rename(const variable_vector_t& from, const variable_vector_t& to) {
        CRAB_ERROR("rename operation not implemented");
    }

    // Normalize the abstract domain if such notion exists.
    virtual void normalize() = 0;

    // Reduce the size of the abstract domain representation.
    virtual void minimize() = 0;

    // Forget variables form the abstract domain
    virtual void forget(const variable_vector_t& variables) = 0;

    // Project the abstract domain onto variables (dual to forget)
    virtual void project(const variable_vector_t& variables) = 0;

    // Make a new copy of var without relating var with new_var
    virtual void expand(variable_t var, variable_t new_var) = 0;
};

template <typename Dom>
class numeric_abstract_domain : public abstract_domain<numeric_abstract_domain<Dom>> {
  public:
    using variable_vector_t = std::vector<variable_t>;

    /**************************** Arithmetic operations *************************/
    // x := y op z
    virtual void apply(operation_t op, variable_t x, variable_t y, variable_t z) = 0;
    // x := y op k
    virtual void apply(operation_t op, variable_t x, variable_t y, number_t k) = 0;
    // x := e
    virtual void assign(variable_t x, linear_expression_t e) = 0;
    // forall cst in csts: assume(cst)
    virtual void operator+=(linear_constraint_system_t csts) = 0;
    // x := y op z
    virtual void apply(bitwise_operation_t op, variable_t x, variable_t y, variable_t z) = 0;
    // x := y op k
    virtual void apply(bitwise_operation_t op, variable_t x, variable_t y, number_t k) = 0;
    // dst := src
    virtual void apply(int_conv_operation_t op, variable_t dst, variable_t src) = 0;
};

template <typename Dom>
class array_abstract_domain : public numeric_abstract_domain<array_abstract_domain<Dom>> {
  public:
    using variable_vector_t = std::vector<variable_t>;
    /**************************** Array operations *******************************/
    // make a fresh array with contents a[j] initialized to val such that
    // j \in [lb_idx,ub_idx) and j % elem_size == 0.
    // elem_size is in bytes.
    virtual void array_init(variable_t a, linear_expression_t elem_size, linear_expression_t lb_idx,
                            linear_expression_t ub_idx, linear_expression_t val) = 0;
    // lhs := a[i] where elem_size is in bytes
    virtual void array_load(variable_t lhs, variable_t a, linear_expression_t elem_size, linear_expression_t i) = 0;
    // a[i] := v where elem_size is in bytes
    virtual void array_store(variable_t a, linear_expression_t elem_size, linear_expression_t i, linear_expression_t v,
                             bool is_singleton) = 0;
    // forall i<=k<j and k % elem_size == 0 :: a[k] := v.
    // elem_size is in bytes
    virtual void array_store_range(variable_t a, linear_expression_t elem_size, linear_expression_t i,
                                   linear_expression_t j, linear_expression_t v) = 0;
    // forall i :: a[i] := b[i]
    virtual void array_assign(variable_t a, variable_t b) = 0;

    /**************************** Backward array operations ******************/
    virtual void backward_array_init(variable_t a, linear_expression_t elem_size, linear_expression_t lb_idx,
                                     linear_expression_t ub_idx, linear_expression_t val, Dom invariant) = 0;
    virtual void backward_array_load(variable_t lhs, variable_t a, linear_expression_t elem_size, linear_expression_t i,
                                     Dom invariant) = 0;
    virtual void backward_array_store(variable_t a, linear_expression_t elem_size, linear_expression_t i,
                                      linear_expression_t v, bool is_singleton, Dom invariant) = 0;
    virtual void backward_array_store_range(variable_t a, linear_expression_t elem_size, linear_expression_t i,
                                            linear_expression_t j, linear_expression_t v, Dom invariant) = 0;
    virtual void backward_array_assign(variable_t a, variable_t b, Dom invariant) = 0;
};

} // end namespace domains
} // end namespace crab
