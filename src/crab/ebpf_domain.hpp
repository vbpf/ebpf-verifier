// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

// This file is eBPF-specific, not derived from CRAB.

#include <functional>
#include <optional>

#include "crab/array_domain.hpp"
#include "crab/split_dbm.hpp"
#include "crab/variable.hpp"
#include "string_constraints.hpp"

namespace crab {

using NumAbsDomain = domains::NumAbsDomain;

struct reg_pack_t;

class ebpf_domain_t final {
    struct TypeDomain;

  public:
    ebpf_domain_t();
    ebpf_domain_t(domains::NumAbsDomain inv, const domains::array_domain_t& stack);

    // Generic abstract domain operations
    static ebpf_domain_t top();
    static ebpf_domain_t bottom();
    void set_to_top();
    void set_to_bottom();
    [[nodiscard]]
    bool is_bottom() const;
    [[nodiscard]]
    bool is_top() const;
    bool operator<=(const ebpf_domain_t& other) const;
    bool operator==(const ebpf_domain_t& other) const;
    void operator|=(ebpf_domain_t&& other);
    void operator|=(const ebpf_domain_t& other);
    ebpf_domain_t operator|(ebpf_domain_t&& other) const;
    ebpf_domain_t operator|(const ebpf_domain_t& other) const&;
    ebpf_domain_t operator|(const ebpf_domain_t& other) &&;
    ebpf_domain_t operator&(const ebpf_domain_t& other) const;
    ebpf_domain_t widen(const ebpf_domain_t& other, bool to_constants) const;
    ebpf_domain_t widening_thresholds(const ebpf_domain_t& other, const thresholds_t& ts);
    ebpf_domain_t narrow(const ebpf_domain_t& other) const;

    typedef bool check_require_func_t(NumAbsDomain&, const linear_constraint_t&, std::string);
    void set_require_check(std::function<check_require_func_t> f);
    bound_t get_loop_count_upper_bound() const;
    static ebpf_domain_t setup_entry(bool init_r1);

    static ebpf_domain_t from_constraints(const std::set<std::string>& constraints, bool setup_constraints);
    string_invariant to_set() const;

    // abstract transformers
    void operator()(const basic_block_t& bb);

    void operator()(const Addable&);
    void operator()(const Assert&);
    void operator()(const Assume&);
    void operator()(const Bin&);
    void operator()(const Call&);
    void operator()(const CallLocal&);
    void operator()(const Callx&);
    void operator()(const Comparable&);
    void operator()(const Exit&);
    void operator()(const FuncConstraint&);
    void operator()(const Jmp&);
    void operator()(const LoadMapFd&);
    void operator()(const Atomic&);
    void operator()(const Mem&);
    void operator()(const ValidDivisor&);
    void operator()(const Packet&);
    void operator()(const TypeConstraint&);
    void operator()(const Un&);
    void operator()(const Undefined&);
    void operator()(const ValidAccess&);
    void operator()(const ValidCall&);
    void operator()(const ValidMapKeyValue&);
    void operator()(const ValidSize&);
    void operator()(const ValidStore&);
    void operator()(const ZeroCtxOffset&);
    void operator()(const IncrementLoopCounter&);

    void initialize_loop_counter(const label_t& label);
    static ebpf_domain_t calculate_constant_limits();

  private:
    // private generic domain functions

    void add(const Reg& reg, int imm, int finite_width);
    void shl(const Reg& reg, int imm, int finite_width);
    void lshr(const Reg& reg, int imm, int finite_width);
    void ashr(const Reg& reg, const linear_expression_t& right_svalue, int finite_width);

    void assume(const linear_constraint_t& cst);

    /// Forget everything we know about the value of a variable.
    void havoc(variable_t v);

    /// Forget everything about all offset variables for a given register.
    void havoc_offsets(const Reg& reg);

    static std::optional<variable_t> get_type_offset_variable(const Reg& reg, int type);
    [[nodiscard]]
    std::optional<variable_t> get_type_offset_variable(const Reg& reg, const NumAbsDomain& inv) const;
    [[nodiscard]]
    std::optional<variable_t> get_type_offset_variable(const Reg& reg) const;

    void scratch_caller_saved_registers();
    void save_callee_saved_registers(const std::string& prefix);
    void restore_callee_saved_registers(const std::string& prefix);
    [[nodiscard]]
    std::optional<uint32_t> get_map_type(const Reg& map_fd_reg) const;
    [[nodiscard]]
    std::optional<uint32_t> get_map_inner_map_fd(const Reg& map_fd_reg) const;
    [[nodiscard]]
    interval_t get_map_key_size(const Reg& map_fd_reg) const;
    [[nodiscard]]
    interval_t get_map_value_size(const Reg& map_fd_reg) const;
    [[nodiscard]]
    interval_t get_map_max_entries(const Reg& map_fd_reg) const;
    void forget_packet_pointers();
    void do_load_mapfd(const Reg& dst_reg, int mapfd, bool maybe_null);

    void assign_valid_ptr(const Reg& dst_reg, bool maybe_null);

    void require(domains::NumAbsDomain& inv, const linear_constraint_t& cst, const std::string& s);

    // memory check / load / store
    void check_access_stack(NumAbsDomain& inv, const linear_expression_t& lb, const linear_expression_t& ub);
    void check_access_context(NumAbsDomain& inv, const linear_expression_t& lb, const linear_expression_t& ub);
    void check_access_packet(NumAbsDomain& inv, const linear_expression_t& lb, const linear_expression_t& ub,
                             std::optional<variable_t> shared_region_size);
    void check_access_shared(NumAbsDomain& inv, const linear_expression_t& lb, const linear_expression_t& ub,
                             variable_t shared_region_size);

    void recompute_stack_numeric_size(NumAbsDomain& inv, const Reg& reg) const;
    void recompute_stack_numeric_size(NumAbsDomain& inv, variable_t type_variable) const;
    void do_load_stack(NumAbsDomain& inv, const Reg& target_reg, const linear_expression_t& addr, int width,
                       const Reg& src_reg);
    void do_load_ctx(NumAbsDomain& inv, const Reg& target_reg, const linear_expression_t& addr_vague, int width);
    void do_load_packet_or_shared(NumAbsDomain& inv, const Reg& target_reg, const linear_expression_t& addr, int width);
    void do_load(const Mem& b, const Reg& target_reg);

    template <typename X, typename Y, typename Z>
    void do_store_stack(domains::NumAbsDomain& inv, const number_t& width, const linear_expression_t& addr, X val_type,
                        Y val_svalue, Z val_uvalue, const std::optional<reg_pack_t>& opt_val_reg);

    template <typename Type, typename SValue, typename UValue>
    void do_mem_store(const Mem& b, Type val_type, SValue val_svalue, UValue val_uvalue,
                      const std::optional<reg_pack_t>& opt_val_reg);

    friend std::ostream& operator<<(std::ostream& o, const ebpf_domain_t& dom);

    static void initialize_packet(ebpf_domain_t& inv);

  private:
    /// Mapping from variables (including registers, types, offsets,
    /// memory locations, etc.) to numeric intervals or relationships
    /// to other variables.
    domains::NumAbsDomain m_inv;

    /// Represents the stack as a memory region, i.e., an array of bytes,
    /// allowing mapping to variable in the m_inv numeric domains
    /// while dealing with overlapping byte ranges.
    domains::array_domain_t stack;

    std::function<check_require_func_t> check_require{};
    bool get_map_fd_range(const Reg& map_fd_reg, int32_t* start_fd, int32_t* end_fd) const;

    struct TypeDomain {
        void assign_type(NumAbsDomain& inv, const Reg& lhs, type_encoding_t t);
        void assign_type(NumAbsDomain& inv, const Reg& lhs, const Reg& rhs);
        void assign_type(NumAbsDomain& inv, const Reg& lhs, const std::optional<linear_expression_t>& rhs);
        void assign_type(NumAbsDomain& inv, std::optional<variable_t> lhs, const Reg& rhs);
        void assign_type(NumAbsDomain& inv, std::optional<variable_t> lhs, const number_t& rhs);

        void havoc_type(NumAbsDomain& inv, const Reg& r);

        [[nodiscard]]
        int get_type(const NumAbsDomain& inv, variable_t v) const;
        [[nodiscard]]
        int get_type(const NumAbsDomain& inv, const Reg& r) const;
        [[nodiscard]]
        int get_type(const NumAbsDomain& inv, const number_t& t) const;

        [[nodiscard]]
        bool has_type(const NumAbsDomain& inv, variable_t v, type_encoding_t type) const;
        [[nodiscard]]
        bool has_type(const NumAbsDomain& inv, const Reg& r, type_encoding_t type) const;
        [[nodiscard]]
        bool has_type(const NumAbsDomain& inv, const number_t& t, type_encoding_t type) const;

        [[nodiscard]]
        bool same_type(const NumAbsDomain& inv, const Reg& a, const Reg& b) const;
        [[nodiscard]]
        bool implies_type(const NumAbsDomain& inv, const linear_constraint_t& a, const linear_constraint_t& b) const;

        [[nodiscard]]
        NumAbsDomain join_over_types(const NumAbsDomain& inv, const Reg& reg,
                                     const std::function<void(NumAbsDomain&, type_encoding_t)>& transition) const;
        [[nodiscard]]
        NumAbsDomain join_by_if_else(const NumAbsDomain& inv, const linear_constraint_t& condition,
                                     const std::function<void(NumAbsDomain&)>& if_true,
                                     const std::function<void(NumAbsDomain&)>& if_false) const;
        void selectively_join_based_on_type(NumAbsDomain& dst, NumAbsDomain& src) const;
        void add_extra_invariant(const NumAbsDomain& dst, std::map<variable_t, interval_t>& extra_invariants,
                                 variable_t type_variable, type_encoding_t type, data_kind_t kind,
                                 const NumAbsDomain& other) const;

        [[nodiscard]]
        bool is_in_group(const NumAbsDomain& inv, const Reg& r, TypeGroup group) const;
    };

    TypeDomain type_inv;
    std::string current_assertion;
}; // end ebpf_domain_t

} // namespace crab
