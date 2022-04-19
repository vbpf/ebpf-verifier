// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

// This file is eBPF-specific, not derived from CRAB.

#include <functional>
#include <optional>
#include <vector>

#include "crab/array_domain.hpp"
#include "crab/split_dbm.hpp"
#include "crab/variable.hpp"
#include "string_constraints.hpp"

using NumAbsDomain = crab::domains::NumAbsDomain;

struct reg_pack_t;

class ebpf_domain_t final {
    struct TypeDomain;

  public:
    ebpf_domain_t();
    ebpf_domain_t(crab::domains::NumAbsDomain inv, crab::domains::array_domain_t stack);

    // Generic abstract domain operations
    static ebpf_domain_t top();
    static ebpf_domain_t bottom();
    void set_to_top();
    void set_to_bottom();
    bool is_bottom() const;
    bool is_top() const;
    bool operator<=(const ebpf_domain_t& other);
    bool operator==(const ebpf_domain_t& other) const;
    void operator|=(ebpf_domain_t&& other);
    void operator|=(const ebpf_domain_t& other);
    ebpf_domain_t operator|(ebpf_domain_t&& other) const;
    ebpf_domain_t operator|(const ebpf_domain_t& other) const&;
    ebpf_domain_t operator|(const ebpf_domain_t& other) &&;
    ebpf_domain_t operator&(const ebpf_domain_t& other) const;
    ebpf_domain_t widen(const ebpf_domain_t& other);
    ebpf_domain_t widening_thresholds(const ebpf_domain_t& other, const crab::iterators::thresholds_t& ts);
    ebpf_domain_t narrow(const ebpf_domain_t& other);

    typedef bool check_require_func_t(NumAbsDomain&, const linear_constraint_t&, std::string);
    void set_require_check(std::function<check_require_func_t> f);
    int get_instruction_count_upper_bound();
    static ebpf_domain_t setup_entry(bool check_termination);

    static ebpf_domain_t from_constraints(const std::set<std::string>& constraints);
    string_invariant to_set();

    // abstract transformers
    void operator()(const basic_block_t& bb, bool check_termination);

    void operator()(const Addable&);
    void operator()(const Assert&);
    void operator()(const Assume&);
    void operator()(const Bin&);
    void operator()(const Call&);
    void operator()(const Comparable&);
    void operator()(const Exit&);
    void operator()(const Jmp&);
    void operator()(const LoadMapFd&);
    void operator()(const LockAdd&);
    void operator()(const Mem&);
    void operator()(const Packet&);
    void operator()(const TypeConstraint&);
    void operator()(const Un&);
    void operator()(const Undefined&);
    void operator()(const ValidAccess&);
    void operator()(const ValidMapKeyValue&);
    void operator()(const ValidSize&);
    void operator()(const ValidStore&);
    void operator()(const ZeroCtxOffset&);

  private:
    // private generic domain functions
    void operator+=(const linear_constraint_t& cst);
    void operator-=(variable_t var);

    void assign(variable_t lhs, variable_t rhs);
    void assign(variable_t x, const linear_expression_t& e);
    void assign(variable_t x, long e);

    void apply(crab::arith_binop_t op, variable_t x, variable_t y, const number_t& z);
    void apply(crab::arith_binop_t op, variable_t x, variable_t y, variable_t z);
    void apply(crab::bitwise_binop_t op, variable_t x, variable_t y, variable_t z);
    void apply(crab::bitwise_binop_t op, variable_t x, variable_t y, const number_t& k);
    void apply(crab::binop_t op, variable_t x, variable_t y, const number_t& z);
    void apply(crab::binop_t op, variable_t x, variable_t y, variable_t z);

    void apply(crab::domains::NumAbsDomain& inv, crab::binop_t op, variable_t x, variable_t y, const number_t& z, bool finite_width = false);
    void apply(crab::domains::NumAbsDomain& inv, crab::binop_t op, variable_t x, variable_t y, variable_t z, bool finite_width = false);

    void add(const Reg& reg, int imm);
    void add(variable_t lhs, variable_t op2);
    void add(variable_t lhs, const number_t& op2);
    void sub(variable_t lhs, variable_t op2);
    void sub(variable_t lhs, const number_t& op2);
    void add_overflow(variable_t lhs, variable_t op2);
    void add_overflow(variable_t lhs, const number_t& op2);
    void sub_overflow(variable_t lhs, variable_t op2);
    void sub_overflow(variable_t lhs, const number_t& op2);
    void neg(variable_t lhs);
    void mul(variable_t lhs, variable_t op2);
    void mul(variable_t lhs, const number_t& op2);
    void div(variable_t lhs, variable_t op2);
    void div(variable_t lhs, const number_t& op2);
    void udiv(variable_t lhs, variable_t op2);
    void udiv(variable_t lhs, const number_t& op2);
    void rem(variable_t lhs, variable_t op2);
    void rem(variable_t lhs, const number_t& op2, bool mod = true);
    void urem(variable_t lhs, variable_t op2);
    void urem(variable_t lhs, const number_t& op2);

    void bitwise_and(variable_t lhs, variable_t op2);
    void bitwise_and(variable_t lhs, const number_t& op2);
    void bitwise_or(variable_t lhs, variable_t op2);
    void bitwise_or(variable_t lhs, const number_t& op2);
    void bitwise_xor(variable_t lhs, variable_t op2);
    void bitwise_xor(variable_t lhs, const number_t& op2);
    void shl_overflow(variable_t lhs, variable_t op2);
    void shl_overflow(variable_t lhs, const number_t& op2);
    void lshr(variable_t lhs, variable_t op2);
    void lshr(variable_t lhs, const number_t& op2);
    void ashr(variable_t lhs, variable_t op2);
    void ashr(variable_t lhs, const number_t& op2);

    void assume(const linear_constraint_t& cst);

    /// Forget everything we know about the value of a variable.
    void havoc(variable_t v);

    /// Forget everything about all offset variables for a given register.
    void havoc_offsets(const Reg& reg);
    void havoc_offsets(NumAbsDomain& inv, const Reg& reg);

    static std::optional<variable_t> get_type_offset_variable(const Reg& reg, int type);
    std::optional<variable_t> get_type_offset_variable(const Reg& reg, const NumAbsDomain& inv) const;
    std::optional<variable_t> get_type_offset_variable(const Reg& reg) const;

    void scratch_caller_saved_registers();
    std::optional<uint32_t> get_map_type(const Reg& map_fd_reg) const;
    std::optional<uint32_t> get_map_inner_map_fd(const Reg& map_fd_reg) const;
    crab::interval_t get_map_key_size(const Reg& map_fd_reg) const;
    crab::interval_t get_map_value_size(const Reg& map_fd_reg) const;
    crab::interval_t get_map_max_entries(const Reg& map_fd_reg) const;
    void forget_packet_pointers();
    void havoc_register(NumAbsDomain& inv, const Reg& reg);
    void do_load_mapfd(const Reg& dst_reg, int mapfd, bool maybe_null);

    void overflow(variable_t lhs);

    void assign_valid_ptr(const Reg& dst_reg, bool maybe_null);

    void require(crab::domains::NumAbsDomain& inv, const linear_constraint_t& cst, const std::string& s);

    // memory check / load / store
    void check_access_stack(NumAbsDomain& inv, const linear_expression_t& lb, const linear_expression_t& ub);
    void check_access_context(NumAbsDomain& inv, const linear_expression_t& lb, const linear_expression_t& ub);
    void check_access_packet(NumAbsDomain& inv, const linear_expression_t& lb, const linear_expression_t& ub,
                             std::optional<variable_t> shared_region_size);
    void check_access_shared(NumAbsDomain& inv, const linear_expression_t& lb, const linear_expression_t& ub,
                             variable_t shared_region_size);

    void recompute_stack_numeric_size(NumAbsDomain& inv, const Reg& reg);
    void recompute_stack_numeric_size(NumAbsDomain& inv, variable_t type_variable);
    void do_load_stack(NumAbsDomain& inv, const Reg& target_reg, const linear_expression_t& addr, int width, const Reg& src_reg);
    void do_load_ctx(NumAbsDomain& inv, const Reg& target_reg, const linear_expression_t& addr_vague, int width);
    void do_load_packet_or_shared(NumAbsDomain& inv, const Reg& target_reg, const linear_expression_t& addr, int width);
    void do_load(const Mem& b, const Reg& target_reg);

    template <typename A, typename X, typename Y>
    void do_store_stack(crab::domains::NumAbsDomain& inv, int width, const A& addr, X val_type, Y val_value,
                        const std::optional<reg_pack_t>& opt_val_reg);

    template <typename Type, typename Value>
    void do_mem_store(const Mem& b, Type val_type, Value val_value, const std::optional<reg_pack_t>& opt_val_reg);

    friend std::ostream& operator<<(std::ostream& o, const ebpf_domain_t& dom);

    static void initialize_packet(ebpf_domain_t& inv);


  private:
    /// Mapping from variables (including registers, types, offsets,
    /// memory locations, etc.) to numeric intervals or relationships
    /// to other variables.
    crab::domains::NumAbsDomain m_inv;

    /// Represents the stack as a memory region, i.e., an array of bytes,
    /// allowing mapping to variable in the m_inv numeric domains
    /// while dealing with overlapping byte ranges.
    crab::domains::array_domain_t stack;

    std::function<check_require_func_t> check_require{};
    bool get_map_fd_range(const Reg& map_fd_reg, int* start_fd, int* end_fd) const;

    struct TypeDomain {
        void assign_type(NumAbsDomain& inv, const Reg& lhs, type_encoding_t t);
        void assign_type(NumAbsDomain& inv, const Reg& lhs, const Reg& rhs);
        void assign_type(NumAbsDomain& inv, const Reg& lhs, const std::optional<linear_expression_t>& rhs);
        void assign_type(NumAbsDomain& inv, std::optional<variable_t> lhs, const Reg& rhs);
        void assign_type(NumAbsDomain& inv, std::optional<variable_t> lhs, int rhs);

        void havoc_type(NumAbsDomain& inv, const Reg& r);

        [[nodiscard]] int get_type(const NumAbsDomain& inv, variable_t v) const;
        [[nodiscard]] int get_type(const NumAbsDomain& inv, const Reg& r) const;
        [[nodiscard]] int get_type(const NumAbsDomain& inv, int t) const;

        [[nodiscard]] bool has_type(const NumAbsDomain& inv, variable_t v, type_encoding_t type) const;
        [[nodiscard]] bool has_type(const NumAbsDomain& inv, const Reg& r, type_encoding_t type) const;
        [[nodiscard]] bool has_type(const NumAbsDomain& inv, int t, type_encoding_t type) const;

        [[nodiscard]] bool same_type(const NumAbsDomain& inv, const Reg& a, const Reg& b) const;
        [[nodiscard]] bool implies_type(const NumAbsDomain& inv, const linear_constraint_t& a, const linear_constraint_t& b) const;

        NumAbsDomain join_over_types(const NumAbsDomain& inv, const Reg& reg,
                                     const std::function<void(NumAbsDomain&, type_encoding_t)>& transition) const;
        NumAbsDomain join_by_if_else(const NumAbsDomain& inv, const linear_constraint_t& condition,
                                     const std::function<void(NumAbsDomain&)>& if_true,
                                     const std::function<void(NumAbsDomain&)>& if_false) const;
        void selectively_join_based_on_type(NumAbsDomain& dst, NumAbsDomain& src) const;
        void add_extra_invariant(NumAbsDomain& dst,
                                 std::map<crab::variable_t, crab::interval_t>& extra_invariants,
                                 variable_t type_variable, type_encoding_t type, crab::data_kind_t kind,
                                 const NumAbsDomain& other) const;

        [[nodiscard]] bool is_in_group(const NumAbsDomain& inv, const Reg& r, TypeGroup group) const;
    };

    TypeDomain type_inv;
    std::string current_assertion;
}; // end ebpf_domain_t
