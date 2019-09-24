/*******************************************************************************
 * Array expansion domain
 *
 * For a given array, map sequences of consecutive bytes to cells
 * consisting of a triple <offset, size, var> where:
 *
 * - offset is an unsigned number
 * - size  is an unsigned number
 * - var is a scalar variable that represents the content of
 *   a[offset,...,offset+size-1]
 *
 * The domain is general enough to represent any possible sequence of
 * consecutive bytes including sequences of bytes starting at the same
 * offsets but different sizes, overlapping sequences starting at
 * different offsets, etc. However, there are some cases that have
 * been implemented an imprecise manner:
 *
 * (1) array store/load with a non-constant index are conservatively ignored.
 * (2) array load from a cell that overlaps with other cells return top.
 ******************************************************************************/

#pragma once

#include <algorithm>
#include <bitset>
#include <functional>
#include <optional>
#include <set>
#include <unordered_map>
#include <vector>

#include "boost/range/algorithm/set_algorithm.hpp"

#include "crab/debug.hpp"
#include "crab/stats.hpp"
#include "crab/types.hpp"

#include "crab/interval.hpp"
#include "crab/patricia_trees.hpp"
#include "crab/split_dbm.hpp"

#include "config.hpp"
#include "dsl_syntax.hpp"
#include "spec_prototypes.hpp"
#include "spec_type_descriptors.hpp"

namespace crab {
namespace domains {

using NumAbsDomain = SplitDBM;

// wrapper for using index_t as patricia_tree keys
class offset_t final {
    index_t _val{};

  public:
    offset_t() = default;
    explicit offset_t(index_t v) : _val(v) {}

    index_t index() const { return _val; }

    bool operator<(const offset_t& o) const { return _val < o._val; }

    bool operator==(const offset_t& o) const { return _val == o._val; }

    bool operator!=(const offset_t& o) const { return !(*this == o); }

    void write(std::ostream& o) const { o << _val; }

    friend std::ostream& operator<<(std::ostream& o, const offset_t& v) {
        v.write(o);
        return o;
    }
};

/*
   Conceptually, a cell is tuple of an array, offset, size, and
   scalar variable such that:

       _scalar = array[_offset, _offset+1,...,_offset+_size-1]

   For simplicity, we don't carry the array inside the cell class.
   Only, offset_map objects can create cells. They will consider the
   array when generating the scalar variable.
*/

class offset_map_t;

class cell_t final {
  private:
    friend class offset_map_t;

    offset_t _offset{};
    unsigned _size{};

    // Only offset_map_t can create cells
    cell_t() = default;

    cell_t(offset_t offset, unsigned size) : _offset(offset), _size(size) {}

    static interval_t to_interval(const offset_t o, unsigned size) {
        return {static_cast<int>(o.index()), static_cast<int>(o.index()) + static_cast<int>(size - 1)};
    }

    interval_t to_interval() const { return to_interval(_offset, _size); }

  public:
    bool is_null() const { return _offset.index() == 0 && _size == 0; }

    offset_t get_offset() const { return _offset; }

    variable_t get_scalar(data_kind_t kind) const { return variable_t::cell_var(kind, _offset.index(), _size); }

    // ignore the scalar variable
    bool operator==(const cell_t& o) const { return to_interval() == o.to_interval(); }

    // ignore the scalar variable
    bool operator<(const cell_t& o) const {
        if (_offset == o._offset)
            return _size < o._size;
        return _offset < o._offset;
    }

    // Return true if [o, o+size) definitely overlaps with the cell,
    // where o is a constant expression.
    bool overlap(const offset_t& o, unsigned size) const {
        interval_t x = to_interval();
        interval_t y = to_interval(o, size);
        bool res = (!(x & y).is_bottom());
        CRAB_LOG("array-expansion-overlap",
                 std::cout << "**Checking if " << x << " overlaps with " << y << "=" << res << "\n";);
        return res;
    }

    // Return true if [symb_lb, symb_ub] may overlap with the cell,
    // where symb_lb and symb_ub are not constant expressions.
    bool symbolic_overlap(const linear_expression_t& symb_lb, const linear_expression_t& symb_ub,
                          const NumAbsDomain& dom) const {

        interval_t x = to_interval();
        assert(x.lb().is_finite());
        assert(x.ub().is_finite());
        linear_expression_t lb(*(x.lb().number()));
        linear_expression_t ub(*(x.ub().number()));

        NumAbsDomain tmp1(dom);
        tmp1 += linear_constraint_t(symb_lb - lb, linear_constraint_t::INEQUALITY); //(lb >= symb_lb);
        tmp1 += linear_constraint_t(lb - symb_lb, linear_constraint_t::INEQUALITY); //(lb <= symb_ub);
        if (!tmp1.is_bottom()) {
            CRAB_LOG("array-expansion-overlap", std::cout << "\tyes.\n";);
            return true;
        }

        NumAbsDomain tmp2(dom);
        tmp2 += linear_constraint_t(symb_ub - ub, linear_constraint_t::INEQUALITY); // (ub >= symb_lb);
        tmp2 += linear_constraint_t(ub - symb_ub, linear_constraint_t::INEQUALITY); // (ub <= symb_ub);
        if (!tmp2.is_bottom()) {
            CRAB_LOG("array-expansion-overlap", std::cout << "\tyes.\n";);
            return true;
        }

        CRAB_LOG("array-expansion-overlap", std::cout << "\tno.\n";);
        return false;
    }

    void write(std::ostream& o) const { o << "cell(" << to_interval() << ")"; }

    friend std::ostream& operator<<(std::ostream& o, const cell_t& c) {
        c.write(o);
        return o;
    }
};

// forward declarations
class ebpf_domain_t;

// Map offsets to cells
class offset_map_t final {
  private:
    friend class ebpf_domain_t;

    using cell_set_t = std::set<cell_t>;

    /*
      The keys in the patricia tree are processing in big-endian
      order. This means that the keys are sorted. Sortedeness is
      very important to perform efficiently operations such as
      checking for overlap cells. Since keys are treated as bit
      patterns, negative offsets can be used but they are treated
      as large unsigned numbers.
    */
    using patricia_tree_t = patricia_tree<offset_t, cell_set_t>;
    using partial_order_t = typename patricia_tree_t::partial_order_t;

    patricia_tree_t _map;

    // for algorithm::lower_bound and algorithm::upper_bound
    struct compare_binding_t {
        bool operator()(const typename patricia_tree_t::binding_t& kv, const offset_t& o) const { return kv.first < o; }
        bool operator()(const offset_t& o, const typename patricia_tree_t::binding_t& kv) const { return o < kv.first; }
        bool operator()(const typename patricia_tree_t::binding_t& kv1,
                        const typename patricia_tree_t::binding_t& kv2) const {
            return kv1.first < kv2.first;
        }
    };

    class domain_po : public partial_order_t {
        bool leq(cell_set_t x, cell_set_t y) {
            {
                cell_set_t z;
                boost::set_difference(x, y, std::inserter(z, z.end()));
                return z.empty();
            }
        }
        // default value is bottom (i.e., empty map)
        bool default_is_top() { return false; }
    }; // class domain_po

    offset_map_t(patricia_tree_t m) : _map(m) {}

    void remove_cell(const cell_t& c);

    void insert_cell(const cell_t& c);

    std::optional<cell_t> get_cell(offset_t o, unsigned size) const;

    cell_t mk_cell(offset_t o, unsigned size);

  public:
    offset_map_t() = default;

    bool empty() const { return _map.empty(); }

    std::size_t size() const { return _map.size(); }

    // leq operator
    bool operator<=(const offset_map_t& o) const {
        domain_po po;
        return _map.leq(o._map, po);
    }

    void operator-=(const cell_t& c) { remove_cell(c); }

    void operator-=(const std::vector<cell_t>& cells) {
        for (unsigned i = 0, e = cells.size(); i < e; ++i) {
            this->operator-=(cells[i]);
        }
    }

    // Return in out all cells that might overlap with (o, size).
    std::vector<cell_t> get_overlap_cells(offset_t o, unsigned size);

    std::vector<cell_t> get_overlap_cells_symbolic_offset(const NumAbsDomain& dom, const linear_expression_t& symb_lb,
                                                          const linear_expression_t& symb_ub) const {
        std::vector<cell_t> out;
        for (auto it = _map.begin(), et = _map.end(); it != et; ++it) {
            const cell_set_t& o_cells = it->second;
            // All cells in o_cells have the same offset. They only differ
            // in the size. If the largest cell overlaps with [offset,
            // offset + size) then the rest of cells are considered to
            // overlap. This is an over-approximation because [offset,
            // offset+size) can overlap with the largest cell but it
            // doesn't necessarily overlap with smaller cells. For
            // efficiency, we assume it overlaps with all.
            cell_t largest_cell;
            for (auto& c : o_cells) {
                if (largest_cell.is_null()) {
                    largest_cell = c;
                } else {
                    assert(c.get_offset() == largest_cell.get_offset());
                    if (largest_cell < c) {
                        largest_cell = c;
                    }
                }
            }
            if (!largest_cell.is_null()) {
                if (largest_cell.symbolic_overlap(symb_lb, symb_ub, dom)) {
                    for (auto& c : o_cells) {
                        out.push_back(c);
                    }
                }
            }
        }
        return out;
    }

    void write(std::ostream& o) const;

    friend std::ostream& operator<<(std::ostream& o, const offset_map_t& m) {
        m.write(o);
        return o;
    }

    /* Operations needed if used as value in a separate_domain */
    bool operator==(const offset_map_t& o) const { return *this <= o && o <= *this; }
    bool is_top() const { return empty(); }
    bool is_bottom() const { return false; }
    /*
       We don't distinguish between bottom and top.
       This is fine because separate_domain only calls bottom if
       operator[] is called over a bottom state. Thus, we will make
       sure that we don't call operator[] in that case.
    */
    static offset_map_t bottom() { return offset_map_t(); }
    static offset_map_t top() { return offset_map_t(); }
};

// We use a global array map
using array_map_t = std::unordered_map<data_kind_t, offset_map_t>;
extern array_map_t global_array_map;
void clear_global_state();

class array_bitset_domain_t final : public writeable {
  private:
    using bits_t = std::bitset<STACK_SIZE>;
    bits_t non_numerical_bytes;

  private:
    offset_map_t& lookup_array_map(data_kind_t kind) { return global_array_map[kind]; }

  public:
    array_bitset_domain_t() { non_numerical_bytes.set(); }

    array_bitset_domain_t(bits_t non_numerical_bytes) : non_numerical_bytes{non_numerical_bytes} {}

    void set_to_top() { non_numerical_bytes.set(); }

    void set_to_bottom() { non_numerical_bytes.reset(); }

    bool is_top() const { return non_numerical_bytes.all(); }

    bool operator<=(array_bitset_domain_t other) {
        return (non_numerical_bytes | other.non_numerical_bytes) == other.non_numerical_bytes;
    }

    bool operator==(const array_bitset_domain_t& other) { return non_numerical_bytes == other.non_numerical_bytes; }

    void operator|=(const array_bitset_domain_t& other) { non_numerical_bytes |= other.non_numerical_bytes; }

    array_bitset_domain_t operator|(array_bitset_domain_t&& other) {
        return non_numerical_bytes | other.non_numerical_bytes;
    }

    array_bitset_domain_t operator|(const array_bitset_domain_t& other) {
        return non_numerical_bytes | other.non_numerical_bytes;
    }

    array_bitset_domain_t operator&(const array_bitset_domain_t& other) {
        return non_numerical_bytes & other.non_numerical_bytes;
    }

    array_bitset_domain_t widen(const array_bitset_domain_t& other) {
        return non_numerical_bytes | other.non_numerical_bytes;
    }

    array_bitset_domain_t narrow(const array_bitset_domain_t& other) {
        return non_numerical_bytes & other.non_numerical_bytes;
    }

    std::pair<bool, bool> uniformity(int lb, int width) {
        bool only_num = true;
        bool only_non_num = true;
        for (int j = 0; j < width; j++) {
            bool b = non_numerical_bytes[lb + j];
            only_num &= !b;
            only_non_num &= b;
        }
        return std::make_pair(only_num, only_non_num);
    }

    void store(int lb, int width, std::optional<number_t> val) {
        for (int i = 0; i < width; i++) {
            if (val && (long)*val == T_NUM)
                non_numerical_bytes.reset(lb + i);
            else
                non_numerical_bytes.set(lb + i);
        }
    }

    void havoc(int lb, int width) {
        for (int i = 0; i < width; i++) {
            non_numerical_bytes.set(lb + i);
        }
    }

    void write(std::ostream& o) {
        o << "Numbers -> {";
        bool first = true;
        for (int i = -STACK_SIZE; i < 0; i++) {
            if (non_numerical_bytes[STACK_SIZE + i])
                continue;
            if (!first)
                o << ", ";
            first = false;
            o << "[" << i;
            int j = i + 1;
            for (; j < 0; j++)
                if (non_numerical_bytes[STACK_SIZE + j])
                    break;
            if (j > i + 1)
                o << "..." << j - 1;
            o << "]";
            i = j;
        }
        o << "}";
    }
};

/**
 * Abstract forward transformer for all statements.
 **/
inline variable_t reg_value(int i) { return variable_t::reg(data_kind_t::values, i); }
inline variable_t reg_offset(int i) { return variable_t::reg(data_kind_t::offsets, i); }
inline variable_t reg_type(int i) { return variable_t::reg(data_kind_t::types, i); }

inline variable_t reg_value(Reg i) { return reg_value(i.v); }
inline variable_t reg_offset(Reg i) { return reg_offset(i.v); }
inline variable_t reg_type(Reg i) { return reg_type(i.v); }

inline linear_constraint_t eq(variable_t a, variable_t b) {
    using namespace dsl_syntax;
    return {a - b, linear_constraint_t::EQUALITY};
}

inline linear_constraint_t neq(variable_t a, variable_t b) {
    using namespace dsl_syntax;
    return {a - b, linear_constraint_t::DISEQUATION};
};

constexpr int MAX_PACKET_OFF = 0xffff;
constexpr int64_t MY_INT_MAX = INT_MAX;
constexpr int64_t PTR_MAX = MY_INT_MAX - MAX_PACKET_OFF;

/** Linear constraint for a pointer comparison.
 */
inline linear_constraint_t jmp_to_cst_offsets_reg(Condition::Op op, variable_t dst_offset, variable_t src_offset) {
    using namespace dsl_syntax;
    using Op = Condition::Op;
    switch (op) {
    case Op::EQ: return eq(dst_offset, src_offset);
    case Op::NE: return neq(dst_offset, src_offset);
    case Op::GE: return dst_offset >= src_offset;
    case Op::SGE: return dst_offset >= src_offset; // pointer comparison is unsigned
    case Op::LE: return dst_offset <= src_offset;
    case Op::SLE: return dst_offset <= src_offset; // pointer comparison is unsigned
    case Op::GT: return dst_offset >= src_offset + 1;
    case Op::SGT: return dst_offset >= src_offset + 1; // pointer comparison is unsigned
    case Op::SLT: return src_offset >= dst_offset + 1;
    // Note: reverse the test as a workaround strange lookup:
    case Op::LT: return src_offset >= dst_offset + 1; // FIX unsigned
    default: return dst_offset - dst_offset == 0;
    }
}

/** Linear constraints for a comparison with a constant.
 */
inline std::vector<linear_constraint_t> jmp_to_cst_imm(Condition::Op op, variable_t dst_value, int imm) {
    using namespace dsl_syntax;
    using Op = Condition::Op;
    switch (op) {
    case Op::EQ: return {dst_value == imm};
    case Op::NE: return {dst_value != imm};
    case Op::GE: return {dst_value >= (unsigned)imm}; // FIX unsigned
    case Op::SGE: return {dst_value >= imm};
    case Op::LE: return {dst_value <= imm, 0 <= dst_value}; // FIX unsigned
    case Op::SLE: return {dst_value <= imm};
    case Op::GT: return {dst_value >= (unsigned)imm + 1}; // FIX unsigned
    case Op::SGT: return {dst_value >= imm + 1};
    case Op::LT: return {dst_value <= (unsigned)imm - 1}; // FIX unsigned
    case Op::SLT: return {dst_value <= imm - 1};
    case Op::SET: throw std::exception();
    case Op::NSET: return {};
    }
    return {};
}

/** Linear constraint for a numerical comparison between registers.
 */
inline std::vector<linear_constraint_t> jmp_to_cst_reg(Condition::Op op, variable_t dst_value, variable_t src_value) {
    using namespace dsl_syntax;
    using Op = Condition::Op;
    switch (op) {
    case Op::EQ: return {eq(dst_value, src_value)};
    case Op::NE: return {neq(dst_value, src_value)};
    case Op::GE: return {dst_value >= src_value}; // FIX unsigned
    case Op::SGE: return {dst_value >= src_value};
    case Op::LE: return {dst_value <= src_value, 0 <= dst_value}; // FIX unsigned
    case Op::SLE: return {dst_value <= src_value};
    case Op::GT: return {dst_value >= src_value + 1}; // FIX unsigned
    case Op::SGT: return {dst_value >= src_value + 1};
    // Note: reverse the test as a workaround strange lookup:
    case Op::LT: return {src_value >= dst_value + 1}; // FIX unsigned
    case Op::SLT: return {src_value >= dst_value + 1};
    case Op::SET: throw std::exception();
    case Op::NSET: return {};
    }
    return {};
}

inline bool is_unsigned_cmp(Condition::Op op) {
    using Op = Condition::Op;
    switch (op) {
    case Op::GE:
    case Op::LE:
    case Op::GT:
    case Op::LT: return true;
    default: return false;
    }
    return {};
}

class ebpf_domain_t final {
  public:
    using variable_vector_t = std::vector<variable_t>;
    typedef void check_require_func_t(NumAbsDomain&, const linear_constraint_t&, std::string);

  private:
    // scalar domain
    NumAbsDomain m_inv;
    array_bitset_domain_t num_bytes;
    std::function<check_require_func_t> check_require{};

  public:
    void set_require_check(std::function<check_require_func_t> f) { check_require = f; }

    static ebpf_domain_t top() {
        ebpf_domain_t abs;
        abs.set_to_top();
        return abs;
    }

    static ebpf_domain_t bottom() {
        ebpf_domain_t abs;
        abs.set_to_bottom();
        return abs;
    }

  private:
    offset_map_t& lookup_array_map(data_kind_t kind) { return global_array_map[kind]; }

    void kill_cells(data_kind_t kind, const std::vector<cell_t>& cells, offset_map_t& offset_map, NumAbsDomain& dom) {
        if (!cells.empty()) {
            // Forget the scalars from the numerical domain
            for (unsigned i = 0, e = cells.size(); i < e; ++i) {
                dom -= cells[i].get_scalar(kind);
            }
            // Remove the cells. If needed again they they will be re-created.
            offset_map -= cells;
        }
    }

  public:
    interval_t to_interval(linear_expression_t expr) { return m_inv.eval_interval(expr); }

    ebpf_domain_t() : m_inv(NumAbsDomain::top()) {}

    ebpf_domain_t(const NumAbsDomain& inv, array_bitset_domain_t num_bytes) : m_inv(inv), num_bytes(num_bytes) {}

    void set_to_top() {
        m_inv.set_to_top();
        num_bytes.set_to_top();
    }

    void set_to_bottom() { m_inv.set_to_bottom(); }

    bool is_bottom() const { return m_inv.is_bottom(); }

    bool is_top() const { return m_inv.is_top() && num_bytes.is_top(); }

    bool operator<=(ebpf_domain_t other) { return m_inv <= other.m_inv && num_bytes <= other.num_bytes; }

    bool operator==(ebpf_domain_t other) {
        return num_bytes == other.num_bytes && m_inv <= other.m_inv && other.m_inv <= m_inv;
    }

    void operator|=(ebpf_domain_t&& other) {
        if (is_bottom()) {
            *this = other;
            return;
        }
        m_inv |= std::move(other.m_inv);
        num_bytes |= std::move(other.num_bytes);
    }

    void operator|=(const ebpf_domain_t& other) {
        ebpf_domain_t tmp{other};
        operator|=(std::move(tmp));
    }

    void operator|=(ebpf_domain_t& other) {
        if (is_bottom()) {
            *this = other;
            return;
        }
        m_inv |= other.m_inv;
        num_bytes |= other.num_bytes;
    }

    ebpf_domain_t operator|(ebpf_domain_t&& other) {
        return ebpf_domain_t(m_inv | other.m_inv, num_bytes | other.num_bytes);
    }

    ebpf_domain_t operator|(const ebpf_domain_t& other) & {
        return ebpf_domain_t(m_inv | other.m_inv, num_bytes | other.num_bytes);
    }

    ebpf_domain_t operator|(const ebpf_domain_t& other) && {
        return ebpf_domain_t(m_inv | other.m_inv, num_bytes | other.num_bytes);
    }

    ebpf_domain_t operator&(ebpf_domain_t other) {
        return ebpf_domain_t(m_inv & std::move(other.m_inv), num_bytes & other.num_bytes);
    }

    ebpf_domain_t widen(ebpf_domain_t other) {
        return ebpf_domain_t(m_inv.widen(other.m_inv), num_bytes | other.num_bytes);
    }

    ebpf_domain_t widening_thresholds(ebpf_domain_t other, const iterators::thresholds_t& ts) {
        return ebpf_domain_t(m_inv.widening_thresholds(other.m_inv, ts), num_bytes | other.num_bytes);
    }

    ebpf_domain_t narrow(ebpf_domain_t other) {
        return ebpf_domain_t(m_inv.narrow(other.m_inv), num_bytes & other.num_bytes);
    }

    interval_t operator[](variable_t x) { return m_inv[x]; }

    void forget(const variable_vector_t& variables) {
        // TODO: forget numerical values
        if (is_bottom() || is_top()) {
            return;
        }

        m_inv.forget(variables);
    }

    void normalize() { CRAB_WARN("array expansion normalize not implemented"); }

    void operator+=(linear_constraint_t cst) { m_inv += cst; }

    void operator-=(variable_t var) { m_inv -= var; }

    void assign(variable_t x, linear_expression_t e) { m_inv.assign(x, e); }
    void assign(variable_t x, int e) { m_inv.set(x, interval_t(number_t(e))); }

    void apply(arith_binop_t op, variable_t x, variable_t y, number_t z) { m_inv.apply(op, x, y, z); }

    void apply(arith_binop_t op, variable_t x, variable_t y, variable_t z) { m_inv.apply(op, x, y, z); }

    void apply(bitwise_binop_t op, variable_t x, variable_t y, variable_t z) { m_inv.apply(op, x, y, z); }

    void apply(bitwise_binop_t op, variable_t x, variable_t y, number_t k) { m_inv.apply(op, x, y, k); }

    template <typename NumOrVar>
    void apply(binop_t op, variable_t x, variable_t y, NumOrVar z) {
        std::visit([&](auto top) { apply(top, x, y, z); }, op);
    }
    // array_operators_api

    void array_load(NumAbsDomain& m_inv, variable_t lhs, data_kind_t kind, linear_expression_t i, int width) {

        if (m_inv.is_bottom())
            return;

        interval_t ii = m_inv.eval_interval(i);
        if (std::optional<number_t> n = ii.singleton()) {
            offset_map_t& offset_map = lookup_array_map(kind);
            long k = (long)*n;
            if (kind == data_kind_t::types) {
                auto [only_num, only_non_num] = num_bytes.uniformity(k, width);
                if (only_num) {
                    m_inv.assign(lhs, T_NUM);
                    return;
                }
                if (!only_non_num || width != 8) {
                    m_inv -= lhs;
                    return;
                }
            }
            offset_t o(k);
            unsigned size = (long)width;
            std::vector<cell_t> cells = offset_map.get_overlap_cells(o, size);
            if (cells.empty()) {
                cell_t c = offset_map.mk_cell(o, size);
                // Here it's ok to do assignment (instead of expand)
                // because c is not a summarized variable. Otherwise, it
                // would be unsound.
                m_inv.assign(lhs, c.get_scalar(kind));
                return;
            } else {
                CRAB_WARN("Ignored read from cell ", kind, "[", o, "...", o.index() + size - 1, "]",
                          " because it overlaps with ", cells.size(), " cells");
                /*
                    TODO: we can apply here "Value Recomposition" 'a la'
                    Mine'06 to construct values of some type from a sequence
                    of bytes. It can be endian-independent but it would more
                    precise if we choose between little- and big-endian.
                */
            }
        } else {
            // TODO: we can be more precise here
            CRAB_WARN("array expansion: ignored array load because of non-constant array index ", i);
        }

        m_inv -= lhs;
    }

    std::optional<std::pair<offset_t, unsigned>>
    kill_and_find_var(NumAbsDomain& m_inv, data_kind_t kind, linear_expression_t i, linear_expression_t elem_size) {
        if (m_inv.is_bottom())
            return {};

        std::optional<std::pair<offset_t, unsigned>> res;

        offset_map_t& offset_map = lookup_array_map(kind);
        interval_t ii = m_inv.eval_interval(i);
        std::vector<cell_t> cells;
        if (std::optional<number_t> n = ii.singleton()) {
            interval_t i_elem_size = m_inv.eval_interval(elem_size);
            std::optional<number_t> n_bytes = i_elem_size.singleton();
            if (n_bytes) {
                unsigned size = (long)(*n_bytes);
                // -- Constant index: kill overlapping cells
                offset_t o((long)*n);
                cells = offset_map.get_overlap_cells(o, size);
                res = std::make_pair(o, size);
            }
        }
        if (!res) {
            // -- Non-constant index: kill overlapping cells
            cells = offset_map.get_overlap_cells_symbolic_offset(m_inv, linear_expression_t(i),
                                                                 linear_expression_t(i + elem_size));
        }
        kill_cells(kind, cells, offset_map, m_inv);

        return res;
    }

    void array_store(NumAbsDomain& m_inv, data_kind_t kind, linear_expression_t idx, linear_expression_t elem_size,
                     linear_expression_t val) {
        auto maybe_cell = kill_and_find_var(m_inv, kind, idx, elem_size);
        if (maybe_cell) {
            // perform strong update
            auto [offset, size] = *maybe_cell;
            if (kind == data_kind_t::types) {
                std::optional<number_t> t = m_inv.eval_interval(val).singleton();
                num_bytes.store(offset.index(), size, t);
            }
            variable_t v = lookup_array_map(kind).mk_cell(offset, size).get_scalar(kind);
            m_inv.assign(v, val);
        }
    }

    void array_havoc(NumAbsDomain& m_inv, data_kind_t kind, linear_expression_t idx, linear_expression_t elem_size) {
        auto maybe_cell = kill_and_find_var(m_inv, kind, idx, elem_size);
        if (maybe_cell && kind == data_kind_t::types) {
            auto [offset, size] = *maybe_cell;
            num_bytes.havoc(offset.index(), size);
        }
    }

    // Perform array stores over an array segment
    void array_store_numbers(NumAbsDomain& m_inv, variable_t _idx, variable_t _width) {

        // TODO: this should be an user parameter.
        const number_t max_num_elems = STACK_SIZE;

        if (is_bottom())
            return;

        std::optional<number_t> idx_n = m_inv[_idx].singleton();
        if (!idx_n) {
            CRAB_WARN("array expansion store range ignored because ", "lower bound is not constant");
            return;
        }

        std::optional<number_t> width = m_inv[_width].singleton();
        if (!width) {
            CRAB_WARN("array expansion store range ignored because ", "upper bound is not constant");
            return;
        }

        if (*idx_n + *width > max_num_elems) {
            CRAB_WARN("array expansion store range ignored because ",
                      "the number of elements is larger than default limit of ", max_num_elems);
            return;
        }
        num_bytes.store((long)*idx_n, (long)*width, std::optional<number_t>(T_NUM));
    }

  private:
    static NumAbsDomain when(NumAbsDomain inv, linear_constraint_t cond) {
        inv += cond;
        return inv;
    }

    void scratch_caller_saved_registers() {
        for (int i = 1; i <= 5; i++) {
            havoc(reg_value(i));
            havoc(reg_offset(i));
            havoc(reg_type(i));
        }
    }

    template <typename NumOrVar>
    void apply(NumAbsDomain& inv, binop_t op, variable_t x, variable_t y, NumOrVar z, bool finite_width = false) {
        inv.apply(op, x, y, z);
        if (finite_width)
            overflow(x);
    }

    void add(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::ADD, lhs, lhs, op2); }
    void add(variable_t lhs, number_t op2) { apply(m_inv, crab::arith_binop_t::ADD, lhs, lhs, op2); }
    void sub(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::SUB, lhs, lhs, op2); }
    void sub(variable_t lhs, number_t op2) { apply(m_inv, crab::arith_binop_t::SUB, lhs, lhs, op2); }
    void add_overflow(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::ADD, lhs, lhs, op2, true); }
    void add_overflow(variable_t lhs, number_t op2) { apply(m_inv, crab::arith_binop_t::ADD, lhs, lhs, op2, true); }
    void sub_overflow(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::SUB, lhs, lhs, op2, true); }
    void sub_overflow(variable_t lhs, number_t op2) { apply(m_inv, crab::arith_binop_t::SUB, lhs, lhs, op2, true); }
    void neg(variable_t lhs) { apply(m_inv, crab::arith_binop_t::MUL, lhs, lhs, (number_t)-1, true); }
    void mul(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::MUL, lhs, lhs, op2, true); }
    void mul(variable_t lhs, number_t op2) { apply(m_inv, crab::arith_binop_t::MUL, lhs, lhs, op2, true); }
    void div(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::SDIV, lhs, lhs, op2, true); }
    void div(variable_t lhs, number_t op2) { apply(m_inv, crab::arith_binop_t::SDIV, lhs, lhs, op2, true); }
    void udiv(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::UDIV, lhs, lhs, op2, true); }
    void udiv(variable_t lhs, number_t op2) { apply(m_inv, crab::arith_binop_t::UDIV, lhs, lhs, op2, true); }
    void rem(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::SREM, lhs, lhs, op2, true); }
    void rem(variable_t lhs, number_t op2, bool mod = true) {
        apply(m_inv, crab::arith_binop_t::SREM, lhs, lhs, op2, mod);
    }
    void urem(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::UREM, lhs, lhs, op2, true); }
    void urem(variable_t lhs, number_t op2) { apply(m_inv, crab::arith_binop_t::UREM, lhs, lhs, op2, true); }

    void bitwise_and(variable_t lhs, variable_t op2) { apply(m_inv, crab::bitwise_binop_t::AND, lhs, lhs, op2); }
    void bitwise_and(variable_t lhs, number_t op2) { apply(m_inv, crab::bitwise_binop_t::AND, lhs, lhs, op2); }
    void bitwise_or(variable_t lhs, variable_t op2) { apply(m_inv, crab::bitwise_binop_t::OR, lhs, lhs, op2); }
    void bitwise_or(variable_t lhs, number_t op2) { apply(m_inv, crab::bitwise_binop_t::OR, lhs, lhs, op2); }
    void bitwise_xor(variable_t lhs, variable_t op2) { apply(m_inv, crab::bitwise_binop_t::XOR, lhs, lhs, op2); }
    void bitwise_xor(variable_t lhs, number_t op2) { apply(m_inv, crab::bitwise_binop_t::XOR, lhs, lhs, op2); }
    void shl_overflow(variable_t lhs, variable_t op2) { apply(m_inv, crab::bitwise_binop_t::SHL, lhs, lhs, op2, true); }
    void shl_overflow(variable_t lhs, number_t op2) { apply(m_inv, crab::bitwise_binop_t::SHL, lhs, lhs, op2, true); }
    void lshr(variable_t lhs, variable_t op2) { apply(m_inv, crab::bitwise_binop_t::LSHR, lhs, lhs, op2); }
    void lshr(variable_t lhs, number_t op2) { apply(m_inv, crab::bitwise_binop_t::LSHR, lhs, lhs, op2); }
    void ashr(variable_t lhs, variable_t op2) { apply(m_inv, crab::bitwise_binop_t::ASHR, lhs, lhs, op2); }
    void ashr(variable_t lhs, number_t op2) { apply(m_inv, crab::bitwise_binop_t::ASHR, lhs, lhs, op2); }

    void assume(const linear_constraint_t& cst) { assume(m_inv, cst); }
    void assume(NumAbsDomain& inv, const linear_constraint_t& cst) { inv += cst; }

    void require(NumAbsDomain& inv, const linear_constraint_t& cst, std::string s) {
        if (check_require)
            check_require(inv, cst, s);
        assume(inv, cst);
    }

    void havoc(variable_t v) { m_inv -= v; }
    void assign(variable_t lhs, variable_t rhs) { m_inv.assign(lhs, rhs); }
    void assign(variable_t lhs, number_t rhs) { m_inv.assign(lhs, rhs); }

    void no_pointer(int i) {
        assign(reg_type(i), T_NUM);
        havoc(reg_offset(i));
    };
    void no_pointer(Reg r) { no_pointer(r.v); }

    static linear_constraint_t is_shared(variable_t v) {
        using namespace dsl_syntax;
        return v > T_SHARED;
    }

    static linear_constraint_t is_pointer(Reg v) {
        using namespace dsl_syntax;
        return reg_type(v) >= T_CTX;
    }
    static linear_constraint_t is_init(Reg v) {
        using namespace dsl_syntax;
        return reg_type(v) > T_UNINIT;
    }
    static linear_constraint_t is_shared(Reg v) { return is_shared(reg_type(v)); }
    static linear_constraint_t is_not_num(Reg v) {
        using namespace dsl_syntax;
        return reg_type(v) > T_NUM;
    }

    void overflow(variable_t lhs) {
        using namespace dsl_syntax;
        auto interval = m_inv[lhs];
        // handle overflow, assuming 64 bit
        number_t max(std::numeric_limits<int64_t>::max() / 2);
        number_t min(std::numeric_limits<int64_t>::min() / 2);
        if (interval.lb() <= min || interval.ub() >= max)
            havoc(lhs);
    }

  public:
    void operator()(Assume const& s) {
        using namespace dsl_syntax;
        Condition cond = s.cond;
        Reg dst = cond.left;
        variable_t dst_value = reg_value(dst);
        variable_t dst_offset = reg_offset(dst);
        variable_t dst_type = reg_type(dst);
        if (std::holds_alternative<Reg>(cond.right)) {
            Reg src = std::get<Reg>(cond.right);
            variable_t src_value = reg_value(src);
            variable_t src_offset = reg_offset(src);
            variable_t src_type = reg_type(src);
            int stype = get_type(src_type);
            int dtype = get_type(dst_type);
            if (stype == dtype) {
                switch (stype) {
                    case T_MAP: break;
                    case T_UNINIT: break;
                    case T_NUM: {
                        if (!is_unsigned_cmp(cond.op))
                            for (const linear_constraint_t& cst : jmp_to_cst_reg(cond.op, dst_value, src_value))
                                m_inv += cst;
                        return;
                    }
                    default: {
                        m_inv += jmp_to_cst_offsets_reg(cond.op, dst_offset, src_offset);
                        return;
                    }
                }
            }
            NumAbsDomain different{m_inv};
            different += neq(dst_type, src_type);

            NumAbsDomain null_src{different};
            null_src += is_pointer(dst);
            NumAbsDomain null_dst{different};
            null_dst += is_pointer(src);

            m_inv += eq(dst_type, src_type);

            NumAbsDomain numbers{m_inv};
            numbers += dst_type == T_NUM;
            if (!is_unsigned_cmp(cond.op))
                for (const linear_constraint_t& cst : jmp_to_cst_reg(cond.op, dst_value, src_value))
                    numbers += cst;

            m_inv += is_pointer(dst);
            m_inv += jmp_to_cst_offsets_reg(cond.op, dst_offset, src_offset);

            m_inv |= std::move(numbers);

            m_inv |= std::move(null_src);
            m_inv |= std::move(null_dst);
        } else {
            int imm = static_cast<int>(std::get<Imm>(cond.right).v);
            for (const linear_constraint_t& cst : jmp_to_cst_imm(cond.op, dst_value, imm))
                assume(cst);
        }
    }

    void operator()(Undefined const& a) {}
    void operator()(Un const& stmt) {
        switch (stmt.op) {
        case Un::Op::LE16:
        case Un::Op::LE32:
        case Un::Op::LE64:
            havoc(reg_value(stmt.dst));
            no_pointer(stmt.dst);
            break;
        case Un::Op::NEG:
            neg(reg_value(stmt.dst));
            no_pointer(stmt.dst);
            break;
        }
    }
    void operator()(Exit const& a) {}
    void operator()(Jmp const& a) {}

    void operator()(const Comparable& s) { require(m_inv, eq(reg_type(s.r1), reg_type(s.r2)), to_string(s)); }

    void operator()(const Addable& s) {
        using namespace dsl_syntax;
        linear_constraint_t cond = reg_type(s.ptr) > T_NUM;
        NumAbsDomain is_ptr{m_inv};
        is_ptr += cond;
        require(is_ptr, reg_type(s.num) == T_NUM, "only numbers can be added to pointers (" + to_string(s) + ")");

        m_inv += cond.negate();
        m_inv |= std::move(is_ptr);
    }

    void operator()(const ValidSize& s) {
        using namespace dsl_syntax;
        variable_t r = reg_value(s.reg);
        require(m_inv, s.can_be_zero ? r >= 0 : r > 0, to_string(s));
    }

    void operator()(const ValidMapKeyValue& s) {
        using namespace dsl_syntax;

        variable_t v = reg_value(s.map_fd_reg);
        apply(m_inv, crab::bitwise_binop_t::LSHR, variable_t::map_value_size(), v, (number_t)14);
        variable_t mk = variable_t::map_key_size();
        apply(m_inv, crab::arith_binop_t::UREM, mk, v, (number_t)(1 << 14));
        lshr(mk, 6);

        variable_t lb = reg_offset(s.access_reg);
        variable_t width = s.key ? variable_t::map_key_size() : variable_t::map_value_size();
        linear_expression_t ub = lb + width;
        std::string m = std::string(" (") + to_string(s) + ")";
        require(m_inv, reg_type(s.access_reg) >= T_STACK, "Only stack or packet can be used as a parameter" + m);
        require(m_inv, reg_type(s.access_reg) <= T_PACKET, "Only stack or packet can be used as a parameter" + m);
        m_inv = check_access_packet(when(m_inv, reg_type(s.access_reg) == T_PACKET), lb, ub, m, false) |
                check_access_stack(when(m_inv, reg_type(s.access_reg) == T_STACK), lb, ub, m);
    }

    void operator()(const ValidAccess& s) {
        using namespace dsl_syntax;

        bool is_comparison_check = s.width == (Value)Imm{0};

        linear_expression_t lb = reg_offset(s.reg) + s.offset;
        linear_expression_t ub;
        if (std::holds_alternative<Imm>(s.width))
            ub = lb + std::get<Imm>(s.width).v;
        else
            ub = lb + reg_value(std::get<Reg>(s.width));
        std::string m = std::string(" (") + to_string(s) + ")";

        NumAbsDomain assume_ptr =
            check_access_packet(when(m_inv, reg_type(s.reg) == T_PACKET), lb, ub, m, is_comparison_check) |
            check_access_stack(when(m_inv, reg_type(s.reg) == T_STACK), lb, ub, m) |
            check_access_shared(when(m_inv, is_shared(reg_type(s.reg))), lb, ub, m, reg_type(s.reg)) |
            check_access_context(when(m_inv, reg_type(s.reg) == T_CTX), lb, ub, m);
        if (is_comparison_check) {
            m_inv |= std::move(assume_ptr);
            return;
        } else if (s.or_null) {
            assume(m_inv, reg_type(s.reg) == T_NUM);
            require(m_inv, reg_value(s.reg) == 0, "Pointers may be compared only to the number 0");
            m_inv |= std::move(assume_ptr);
            return;
        } else {
            require(m_inv, reg_type(s.reg) > T_NUM, "Only pointers can be dereferenced");
        }
        m_inv = std::move(assume_ptr);
    }

    NumAbsDomain check_access_packet(NumAbsDomain inv, linear_expression_t lb, linear_expression_t ub, std::string s,
                                     bool is_comparison_check) {
        using namespace dsl_syntax;
        require(inv, lb >= variable_t::meta_offset(), std::string("Lower bound must be higher than meta_offset") + s);
        if (is_comparison_check)
            require(inv, ub <= MAX_PACKET_OFF,
                    std::string("Upper bound must be lower than ") + std::to_string(MAX_PACKET_OFF) + s);
        else
            require(inv, ub <= variable_t::packet_size(),
                    std::string("Upper bound must be lower than meta_offset") + s);
        return inv;
    }

    NumAbsDomain check_access_stack(NumAbsDomain inv, linear_expression_t lb, linear_expression_t ub, std::string s) {
        using namespace dsl_syntax;
        require(inv, lb >= 0, std::string("Lower bound must be higher than 0") + s);
        require(inv, ub <= STACK_SIZE, std::string("Upper bound must be lower than STACK_SIZE") + s);
        return inv;
    }

    NumAbsDomain check_access_shared(NumAbsDomain inv, linear_expression_t lb, linear_expression_t ub, std::string s,
                                     variable_t reg_type) {
        using namespace dsl_syntax;
        require(inv, lb >= 0, std::string("Lower bound must be higher than 0") + s);
        require(inv, ub <= reg_type, std::string("Upper bound must be lower than ") + reg_type.name() + s);
        return inv;
    }

    NumAbsDomain check_access_context(NumAbsDomain inv, linear_expression_t lb, linear_expression_t ub, std::string s) {
        using namespace dsl_syntax;
        require(inv, lb >= 0, std::string("Lower bound must be higher than 0") + s);
        require(inv, ub <= global_program_info.descriptor.size,
                std::string("Upper bound must be lower than ") + std::to_string(global_program_info.descriptor.size) +
                    s);
        return inv;
    }

    void operator()(const ValidStore& s) {
        using namespace dsl_syntax;
        linear_constraint_t cond = reg_type(s.mem) != T_STACK;

        NumAbsDomain non_stack{m_inv};
        non_stack += cond;
        require(non_stack, reg_type(s.val) == T_NUM, "Only numbers can be stored to externally-visible regions");

        m_inv += cond.negate();
        m_inv |= std::move(non_stack);
    }

    void operator()(const TypeConstraint& s) {
        using namespace dsl_syntax;
        variable_t t = reg_type(s.reg);
        std::string str = to_string(s);
        switch (s.types) {
        case TypeGroup::num: require(m_inv, t == T_NUM, str); break;
        case TypeGroup::map_fd: require(m_inv, t == T_MAP, str); break;
        case TypeGroup::ctx: require(m_inv, t == T_CTX, str); break;
        case TypeGroup::packet: require(m_inv, t == T_PACKET, str); break;
        case TypeGroup::stack: require(m_inv, t == T_STACK, str); break;
        case TypeGroup::shared: require(m_inv, t > T_SHARED, str); break;
        case TypeGroup::non_map_fd: require(m_inv, t >= T_NUM, str); break;
        case TypeGroup::mem: require(m_inv, t >= T_STACK, str); break;
        case TypeGroup::mem_or_num:
            require(m_inv, t >= T_NUM, str);
            require(m_inv, t != T_CTX, str);
            break;
        case TypeGroup::ptr: require(m_inv, t >= T_CTX, str); break;
        case TypeGroup::ptr_or_num: require(m_inv, t >= T_NUM, str); break;
        case TypeGroup::stack_or_packet:
            require(m_inv, t >= T_STACK, str);
            require(m_inv, t <= T_PACKET, str);
            break;
        }
    }

    void operator()(Assert const& stmt) { std::visit(*this, stmt.cst); };

    void operator()(Packet const& a) {
        assign(reg_type(0), T_NUM);
        havoc(reg_offset(0));
        havoc(reg_value(0));
        scratch_caller_saved_registers();
    }

    NumAbsDomain do_load_packet_or_shared(NumAbsDomain inv, Reg target, linear_expression_t addr, int width) {
        if (inv.is_bottom())
            return inv;

        inv.assign(reg_type(target), T_NUM);
        inv -= reg_offset(target);
        inv -= reg_value(target);
        return inv;
    }

    NumAbsDomain do_load_ctx(NumAbsDomain inv, Reg target, linear_expression_t addr_vague, int width) {
        using namespace dsl_syntax;
        if (inv.is_bottom())
            return inv;

        ptype_descr desc = global_program_info.descriptor;

        variable_t target_value = reg_value(target);
        variable_t target_offset = reg_offset(target);
        variable_t target_type = reg_type(target);

        inv -= target_value;

        if (desc.end < 0) {
            inv -= target_offset;
            inv.assign(target_type, T_NUM);
            return inv;
        }

        interval_t interval = inv.eval_interval(addr_vague);
        std::optional<number_t> maybe_addr = interval.singleton();

        bool may_touch_ptr = interval[desc.data] || interval[desc.end] || interval[desc.end];

        if (!maybe_addr) {
            inv -= target_offset;
            if (may_touch_ptr)
                inv -= target_type;
            else
                inv.assign(target_type, T_NUM);
            return inv;
        }

        number_t addr = *maybe_addr;

        if (addr == desc.data) {
            inv.assign(target_offset, 0);
        } else if (addr == desc.end) {
            inv.assign(target_offset, variable_t::packet_size());
        } else if (addr == desc.meta) {
            inv.assign(target_offset, variable_t::meta_offset());
        } else {
            inv -= target_offset;
            if (may_touch_ptr)
                inv -= target_type;
            else
                inv.assign(target_type, T_NUM);
            return inv;
        }
        inv.assign(target_type, T_PACKET);
        inv += 4098 <= target_value;
        inv += target_value <= PTR_MAX;
        return inv;
    }

    NumAbsDomain do_load_stack(NumAbsDomain inv, Reg target, linear_expression_t addr, int width) {
        if (inv.is_bottom())
            return inv;

        if (width == 8) {
            array_load(inv, reg_type(target), data_kind_t::types, addr, width);
            array_load(inv, reg_value(target), data_kind_t::values, addr, width);
            array_load(inv, reg_offset(target), data_kind_t::offsets, addr, width);
        } else {
            array_load(inv, reg_type(target), data_kind_t::types, addr, width);
            inv -= reg_value(target);
            inv -= reg_offset(target);
        }
        return inv;
    }

    void do_load(Mem const& b, Reg target) {
        using namespace dsl_syntax;
        Reg mem_reg = b.access.basereg;
        int width = (int)b.access.width;
        int offset = (int)b.access.offset;
        linear_expression_t addr = reg_offset(mem_reg) + (number_t)offset;
        variable_t mem_reg_type = reg_type(mem_reg);

        if (mem_reg.v == 10) {
            m_inv = do_load_stack(std::move(m_inv), target, addr, width);
            return;
        }

        int type = get_type(mem_reg_type);
        if (type == T_UNINIT) {
            return;
        }

        switch (type) {
            case T_UNINIT: {
                m_inv = do_load_ctx(when(m_inv, mem_reg_type == T_CTX), target, addr, width) |
                        do_load_packet_or_shared(when(m_inv, mem_reg_type >= T_PACKET), target, addr, width) |
                        do_load_stack(when(m_inv, mem_reg_type == T_STACK), target, addr, width);
                return;
            }
            case T_MAP: return;
            case T_NUM: return;
            case T_CTX: m_inv = do_load_ctx(std::move(m_inv), target, addr, width); break;
            case T_STACK: m_inv = do_load_stack(std::move(m_inv), target, addr, width); break;
            default: m_inv = do_load_packet_or_shared(std::move(m_inv), target, addr, width); break;
        }
    }

    int get_type(variable_t v) {
        auto res = m_inv[v].singleton();
        if (!res)
            return T_UNINIT;
        return (int)*res;
    }

    int get_type(int t) { return t; }

    template <typename A, typename X, typename Y, typename Z>
    void do_store_stack(NumAbsDomain& inv, int width, A addr, X val_type, Y val_value,
                        std::optional<Z> opt_val_offset) {
        array_store(inv, data_kind_t::types, addr, width, val_type);
        if (width == 8) {
            array_store(inv, data_kind_t::values, addr, width, val_value);
            if (opt_val_offset && get_type(val_type) != T_NUM)
                array_store(inv, data_kind_t::offsets, addr, width, *opt_val_offset);
            else
                array_havoc(inv, data_kind_t::offsets, addr, width);
        } else {
            array_havoc(inv, data_kind_t::values, addr, width);
            array_havoc(inv, data_kind_t::offsets, addr, width);
        }
    }

    void operator()(Mem const& b) {
        if (std::holds_alternative<Reg>(b.value)) {
            Reg data_reg = std::get<Reg>(b.value);
            if (b.is_load) {
                do_load(b, data_reg);
            } else {
                do_mem_store(b, reg_type(data_reg), reg_value(data_reg), reg_offset(data_reg));
            }
        } else {
            do_mem_store(b, T_NUM, std::get<Imm>(b.value).v, {});
        }
    }

    template <typename Type, typename Value>
    void do_mem_store(Mem const& b, Type val_type, Value val_value, std::optional<variable_t> opt_val_offset) {
        using namespace dsl_syntax;
        Reg mem_reg = b.access.basereg;
        int width = (int)b.access.width;
        int offset = (int)b.access.offset;
        if (mem_reg.v == 10) {
            int addr = STACK_SIZE + offset;
            do_store_stack(m_inv, width, addr, val_type, val_value, opt_val_offset);
            return;
        }
        variable_t mem_reg_type = reg_type(mem_reg);
        linear_expression_t addr = reg_offset(mem_reg) + (number_t)offset;
        switch (get_type(mem_reg_type)) {
            case T_STACK: do_store_stack(m_inv, width, addr, val_type, val_value, opt_val_offset); return;
            case T_UNINIT: { //maybe stack
                NumAbsDomain assume_not_stack(m_inv);
                assume_not_stack += mem_reg_type != T_STACK;
                m_inv += mem_reg_type == T_STACK;
                if (!m_inv.is_bottom()) {
                    do_store_stack(m_inv, width, addr, val_type, val_value, opt_val_offset);
                }
                m_inv |= std::move(assume_not_stack);
            }
            default: break;
        }
    }

    void operator()(LockAdd const& a) {
        // nothing to do here
    }

    void operator()(Call const& call) {
        using namespace dsl_syntax;
        for (ArgSingle param : call.singles) {
            switch (param.kind) {
            case ArgSingle::Kind::ANYTHING: break;
            // should have been done in the assertion
            case ArgSingle::Kind::MAP_FD: break;
            case ArgSingle::Kind::PTR_TO_MAP_KEY: break;
            case ArgSingle::Kind::PTR_TO_MAP_VALUE: break;
            case ArgSingle::Kind::PTR_TO_CTX: break;
            }
        }
        for (ArgPair param : call.pairs) {
            switch (param.kind) {
            case ArgPair::Kind::PTR_TO_MEM_OR_NULL:
            case ArgPair::Kind::PTR_TO_MEM:
                // TODO: check that initialzied
                break;

            case ArgPair::Kind::PTR_TO_UNINIT_MEM: {
                variable_t addr = reg_offset(param.mem);
                variable_t width = reg_value(param.size);
                interval_t t = m_inv[reg_type(param.mem)];
                if (t[T_STACK]) {
                    array_havoc(m_inv, data_kind_t::types, addr, width);
                    array_havoc(m_inv, data_kind_t::values, addr, width);
                    array_havoc(m_inv, data_kind_t::offsets, addr, width);
                    if (t.singleton()) {
                        array_store_numbers(m_inv, addr, width);
                    }
                }
            }
            }
        }
        scratch_caller_saved_registers();
        variable_t r0 = reg_value(0);
        havoc(r0);
        if (call.returns_map) {
            // no support for map-in-map yet:
            //   if (machine.info.map_defs.at(map_type).type == MapType::ARRAY_OF_MAPS
            //    || machine.info.map_defs.at(map_type).type == MapType::HASH_OF_MAPS) { }
            // This is the only way to get a null pointer - note the `<=`:
            m_inv += 0 <= r0;
            m_inv += r0 <= PTR_MAX;
            assign(reg_offset(0), 0);
            assign(reg_type(0), variable_t::map_value_size());
        } else {
            havoc(reg_offset(0));
            assign(reg_type(0), T_NUM);
            // assume(r0 < 0); for VOID, which is actually "no return if succeed".
        }
    }

    void operator()(LoadMapFd const& ins) {
        Reg dst = ins.dst;
        assign(reg_type(dst), T_MAP);
        assign(reg_value(dst), ins.mapfd);
        havoc(reg_offset(dst));
    }

    void operator()(Bin const& bin) {
        using namespace dsl_syntax;

        Reg dst = bin.dst;
        variable_t dst_value = reg_value(dst);
        variable_t dst_offset = reg_offset(dst);
        variable_t dst_type = reg_type(dst);

        if (std::holds_alternative<Imm>(bin.v)) {
            // dst += K
            int imm = static_cast<int>(std::get<Imm>(bin.v).v);
            switch (bin.op) {
            case Bin::Op::MOV:
                assign(dst_value, imm);
                no_pointer(dst);
                break;
            case Bin::Op::ADD:
                if (imm == 0)
                    return;
                add_overflow(dst_value, imm);
                add(dst_offset, imm);
                break;
            case Bin::Op::SUB:
                if (imm == 0)
                    return;
                sub_overflow(dst_value, imm);
                sub(dst_offset, imm);
                break;
            case Bin::Op::MUL:
                mul(dst_value, imm);
                no_pointer(dst);
                break;
            case Bin::Op::DIV:
                div(dst_value, imm);
                no_pointer(dst);
                break;
            case Bin::Op::MOD:
                rem(dst_value, imm);
                no_pointer(dst);
                break;
            case Bin::Op::OR:
                bitwise_or(dst_value, imm);
                no_pointer(dst);
                break;
            case Bin::Op::AND:
                // FIX: what to do with ptr&-8 as in counter/simple_loop_unrolled?
                bitwise_and(dst_value, imm);
                if ((int32_t)imm > 0) {
                    assume(dst_value <= imm);
                    assume(0 <= dst_value);
                }
                no_pointer(dst);
                break;
            case Bin::Op::LSH: {
                shl_overflow(dst_value, imm); // avoid signedness and overflow issues in shl_overflow(dst_value, imm);
                no_pointer(dst);
                break;
            }
            case Bin::Op::RSH:
                havoc(dst_value); // avoid signedness and overflow issues in lshr(dst_value, imm);
                no_pointer(dst);
                break;
            case Bin::Op::ARSH:
                havoc(dst_value); // avoid signedness and overflow issues in ashr(dst_value, imm); // = (int64_t)dst >>
                                  // imm;
                // assume(dst_value <= (1 << (64 - imm)));
                // assume(dst_value >= -(1 << (64 - imm)));
                no_pointer(dst);
                break;
            case Bin::Op::XOR:
                bitwise_xor(dst_value, imm);
                no_pointer(dst);
                break;
            }
        } else {
            // dst op= src
            Reg src = std::get<Reg>(bin.v);
            variable_t src_value = reg_value(src);
            variable_t src_offset = reg_offset(src);
            variable_t src_type = reg_type(src);
            switch (bin.op) {
            case Bin::Op::ADD: {
                auto stype = get_type(src_type);
                auto dtype = get_type(dst_type);
                if (stype == T_NUM && dtype == T_NUM) {
                    add_overflow(dst_value, src_value);
                } else if (dtype == T_NUM) {
                    apply(m_inv, crab::arith_binop_t::ADD, dst_value, src_value, dst_value, true);
                    apply(m_inv, crab::arith_binop_t::ADD, dst_offset, src_offset, dst_value, false);
                    m_inv.assign(dst_type, src_type);
                } else if (stype == T_NUM) {
                    add_overflow(dst_value, src_value);
                    add(dst_offset, src_value);
                } else {
                    havoc(dst_type);
                    havoc(dst_value);
                    havoc(dst_offset);
                }
                break;
            }
            case Bin::Op::SUB: {
                auto stype = get_type(src_type);
                auto dtype = get_type(dst_type);
                if (dtype == T_NUM && stype == T_NUM) {
                    sub_overflow(dst_value, src_value);
                } else if (stype == T_NUM) {
                    sub_overflow(dst_value, src_value);
                    sub(dst_offset, src_value);
                } else if (stype == dtype && stype < 0) { // subtracting non-shared poitners
                    apply(m_inv, crab::arith_binop_t::SUB, dst_value, dst_offset, src_offset, true);
                    havoc(dst_offset);
                    assign(dst_type, T_NUM);
                } else {
                    havoc(dst_type);
                    havoc(dst_value);
                    havoc(dst_offset);
                }
                break;
            }
            case Bin::Op::MUL:
                mul(dst_value, src_value);
                no_pointer(dst);
                break;
            case Bin::Op::DIV:
                // DIV is not checked for zerodiv
                div(dst_value, src_value);
                no_pointer(dst);
                break;
            case Bin::Op::MOD:
                // See DIV comment
                rem(dst_value, src_value);
                no_pointer(dst);
                break;
            case Bin::Op::OR:
                bitwise_or(dst_value, src_value);
                no_pointer(dst);
                break;
            case Bin::Op::AND:
                bitwise_and(dst_value, src_value);
                no_pointer(dst);
                break;
            case Bin::Op::LSH:
                shl_overflow(dst_value, src_value);
                no_pointer(dst);
                break;
            case Bin::Op::RSH:
                havoc(dst_value);
                no_pointer(dst);
                break;
            case Bin::Op::ARSH:
                havoc(dst_value);
                no_pointer(dst);
                break;
            case Bin::Op::XOR:
                bitwise_xor(dst_value, src_value);
                no_pointer(dst);
                break;
            case Bin::Op::MOV:
                assign(dst_value, src_value);
                assign(dst_offset, src_offset);
                assign(dst_type, src_type);
                break;
            }
        }
        if (!bin.is64) {
            bitwise_and(dst_value, UINT32_MAX);
        }
    }

    NumAbsDomain get_content_domain() const { return m_inv; }

    NumAbsDomain& get_content_domain() { return m_inv; }

    friend std::ostream& operator<<(std::ostream& o, ebpf_domain_t dom) {
        if (dom.is_bottom()) {
            o << "_|_";
        } else {
            o << dom.m_inv << "\n" << dom.num_bytes;
        }
        return o;
    }

    void rename(const variable_vector_t& from, const variable_vector_t& to) { m_inv.rename(from, to); }

    static ebpf_domain_t setup_entry() {
        std::cerr << "meta: " << global_program_info.descriptor.meta << "\n";
        std::cerr << "data: " << global_program_info.descriptor.data << "\n";
        std::cerr << "end: " << global_program_info.descriptor.end << "\n";
        std::cerr << "ctx size: " << global_program_info.descriptor.size << "\n";
        using namespace dsl_syntax;

        // intra_abs_transformer<AbsDomain>(inv);
        ebpf_domain_t inv;
        inv += STACK_SIZE <= reg_value(10);
        inv.assign(reg_offset(10), STACK_SIZE);
        inv.assign(reg_type(10), T_STACK);

        inv += 1 <= reg_value(1);
        inv += reg_value(1) <= PTR_MAX;
        inv.assign(reg_offset(1), 0);
        inv.assign(reg_type(1), T_CTX);

        inv += 0 <= variable_t::packet_size();
        inv += variable_t::packet_size() < MAX_PACKET_OFF;
        if (global_program_info.descriptor.meta >= 0) {
            inv += variable_t::meta_offset() <= 0;
            inv += variable_t::meta_offset() >= -4098;
        } else {
            inv.assign(variable_t::meta_offset(), 0);
        }
        return inv;
    }

    bool entail(const linear_constraint_t& cst) { return m_inv.entail(cst); }

    bool intersect(const linear_constraint_t& cst) { return m_inv.intersect(cst); }

}; // end ebpf_domain_t

} // namespace domains
} // namespace crab
