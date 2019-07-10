#pragma once

#include "crab/debug.hpp"
#include "crab/os.hpp"

#include <boost/make_shared.hpp>
#include <boost/optional.hpp>
#include <memory>
#include <iosfwd>

/* Basic type definitions */

namespace crab {

enum variable_type { INT_TYPE, ARR_INT_TYPE, UNK_TYPE };

inline crab_os &operator<<(crab_os &o, variable_type t) {
    switch (t) {
    case INT_TYPE:
        o << "int";
        break;
    case ARR_INT_TYPE:
        o << "arr_int";
        break;
    default:
        o << "unknown";
        break;
    }
    return o;
}

typedef enum {
    BINOP_ADD,
    BINOP_SUB,
    BINOP_MUL,
    BINOP_SDIV,
    BINOP_UDIV,
    BINOP_SREM,
    BINOP_UREM,
    BINOP_AND,
    BINOP_OR,
    BINOP_XOR,
    BINOP_SHL,
    BINOP_LSHR,
    BINOP_ASHR,
    BINOP_FUNCTION
} binary_operation_t;

typedef enum { CAST_TRUNC, CAST_SEXT, CAST_ZEXT } cast_operation_t;

inline crab::crab_os &operator<<(crab::crab_os &o, binary_operation_t op) {
    switch (op) {
    case BINOP_ADD:
        o << "+";
        break;
    case BINOP_SUB:
        o << "-";
        break;
    case BINOP_MUL:
        o << "*";
        break;
    case BINOP_SDIV:
        o << "/";
        break;
    case BINOP_UDIV:
        o << "/_u";
        break;
    case BINOP_SREM:
        o << "%";
        break;
    case BINOP_UREM:
        o << "%_u";
        break;
    case BINOP_AND:
        o << "&";
        break;
    case BINOP_OR:
        o << "|";
        break;
    case BINOP_XOR:
        o << "^";
        break;
    case BINOP_SHL:
        o << "<<";
        break;
    case BINOP_LSHR:
        o << ">>_l";
        break;
    case BINOP_ASHR:
        o << ">>_r";
        break;
    case BINOP_FUNCTION:
        o << "uf";
        break;
    default:
        CRAB_ERROR("unexpected binary operation ", op);
    }
    return o;
}

inline crab::crab_os &operator<<(crab::crab_os &o, cast_operation_t op) {
    switch (op) {
    case CAST_TRUNC:
        o << "trunc";
        break;
    case CAST_SEXT:
        o << "sext";
        break;
    case CAST_ZEXT:
        o << "zext";
        break;
    default:
        CRAB_ERROR("unexpected cast operation", op);
    }
    return o;
}

template <typename T>
inline boost::optional<T> conv_op(binary_operation_t op);

template <typename T>
inline boost::optional<T> conv_op(cast_operation_t op);

} // end namespace crab

namespace ikos {
// Numerical type for indexed objects
typedef uint64_t index_t;

// Interface for writeable objects
class writeable {
  public:
    virtual void write(crab::crab_os &o) = 0;
    virtual ~writeable() {}
}; // class writeable

inline crab::crab_os &operator<<(crab::crab_os &o, writeable &x) {
    x.write(o);
    return o;
}

// Container for typed variables used by the crab abstract domains
// and linear_constraints.
template <typename Number, typename VariableName>
class variable {
    // XXX: template parameter Number is required even if the class
    // does not use it.  This allows, e.g., linear_constraint to
    // deduce the kind of Number from constraints like x < y.

  public:
    using variable_t = variable<Number, VariableName>;
    using index_t = typename VariableName::index_t;
    using bitwidth_t = unsigned;
    using type_t = crab::variable_type;
    using number_t = Number;
    using varname_t = VariableName;

  private:
    VariableName _n;
    type_t _type;
    bitwidth_t _width;

  public:
    /**
     * DO NOT USE this constructor to create a CFG since all CFG
     * statements must be strongly typed.  This constructor is
     * intended to be used only abstract domains to generate temporary
     * variables.
     **/
    explicit variable(const VariableName &n) : _n(n), _type(crab::UNK_TYPE), _width(0) {}

  public:
    variable(const VariableName &n, type_t type) : _n(n), _type(type), _width(0) {}

    variable(const VariableName &n, type_t type, bitwidth_t width) : _n(n), _type(type), _width(width) {}

    variable(const variable_t &o) : _n(o._n), _type(o._type), _width(o._width) {}

    variable(variable_t &&o) : _n(std::move(o._n)), _type(std::move(o._type)), _width(std::move(o._width)) {}

    variable_t &operator=(const variable_t &o) {
        if (this != &o) {
            _n = o._n;
            _type = o._type;
            _width = o._width;
        }
        return *this;
    }

    bool is_typed() const { return _type != crab::UNK_TYPE; }

    bool is_array_type() const { return is_typed() && _type >= crab::ARR_INT_TYPE; }

    bool is_int_type() const { return _type == crab::INT_TYPE; }

    type_t get_type() const { return _type; }

    bool has_bitwidth() const { return _width > 0; }

    bitwidth_t get_bitwidth() const { return _width; }

    const VariableName &name() const { return _n; }

    // Cannot be const because from VariableName we might want to
    // access to its variable factory to create e.g., new
    // VariableName's.
    VariableName &name() { return _n; }

    index_t index() const { return _n.index(); }

    std::size_t hash() const { return (size_t)_n.index(); }

    bool operator==(const variable_t &o) const { return _n.index() == o._n.index(); }

    bool operator!=(const variable_t &o) const { return (!(operator==(o))); }

    bool operator<(const variable_t &o) const { return _n.index() < o._n.index(); }

    void write(crab::crab_os &o) const { o << _n; }

}; // class variable

template <typename Number, typename VariableName>
class variable_ref {
  public:
    using variable_t = variable<Number, VariableName>;
    using index_t = typename variable_t::index_t;
    using bitwidth_t = typename variable_t::bitwidth_t;
    using type_t = typename variable_t::type_t;
    using variable_ref_t = variable_ref<Number, VariableName>;
    using number_t = Number;
    using varname_t = VariableName;

  private:
    std::shared_ptr<variable_t> m_v{};

  public:
    variable_ref() {}

    variable_ref(variable_t v) : m_v(std::make_shared<variable_t>(v)) {}

    bool is_null() const { return !m_v; }

    variable_t get() const {
        assert(!is_null());
        return *m_v;
    }

    bool is_typed() const {
        assert(!is_null());
        return m_v->is_typed();
    }

    bool is_array_type() const {
        assert(!is_null());
        return m_v->is_array_type();
    }

    bool is_int_type() const {
        assert(!is_null());
        return m_v->is_int_type();
    }

    type_t get_type() const {
        assert(!is_null());
        return m_v->get_type();
    }

    bool has_bitwidth() const {
        assert(!is_null());
        return m_v->has_bitwidth();
    }

    bitwidth_t get_bitwidth() const {
        assert(!is_null());
        return m_v->get_bitwidth();
    }

    const VariableName &name() const {
        assert(!is_null());
        return m_v->name();
    }

    VariableName &name() {
        assert(!is_null());
        return m_v->name();
    }

    index_t index() const {
        assert(!is_null());
        return m_v->index();
    }

    std::size_t hash() const {
        assert(!is_null());
        return m_v->hash();
    }

    bool operator==(const variable_ref_t &o) const {
        assert(!is_null());
        return m_v->operator==(o);
    }

    bool operator!=(const variable_ref_t &o) const {
        assert(!is_null());
        return m_v->operator!=(o);
    }

    bool operator<(const variable_ref_t &o) const {
        assert(!is_null());
        return m_v->operator<(o);
    }

    void write(crab::crab_os &o) const { return m_v->write(o); }
}; // class variable_ref

template <typename Number, typename VariableName>
inline size_t hash_value(const variable<Number, VariableName> &v) {
    return v.hash();
}

template <typename Number, typename VariableName>
inline size_t hash_value(const variable_ref<Number, VariableName> &v) {
    return v.hash();
}

template <typename Number, typename VariableName>
inline crab::crab_os &operator<<(crab::crab_os &o, const variable<Number, VariableName> &v) {
    v.write(o);
    return o;
}

template <typename Number, typename VariableName>
inline crab::crab_os &operator<<(crab::crab_os &o, const variable_ref<Number, VariableName> &v) {
    v.write(o);
    return o;
}

} // end namespace ikos

namespace crab {
namespace domains {
using namespace ikos;
}
} // namespace crab
