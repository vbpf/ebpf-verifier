// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include <string>

namespace crab {

// data_kind_t is eBPF-specific.
enum class data_kind_t {
    types,
    svalues,
    uvalues,
    ctx_offsets,
    map_fds,
    packet_offsets,
    shared_offsets,
    stack_offsets,
    shared_region_sizes,
    stack_numeric_sizes
};

std::string name_of(data_kind_t kind);
data_kind_t regkind(const std::string& s);
std::ostream& operator<<(std::ostream& o, const data_kind_t& s);

// The exact numbers are taken advantage of in ebpf_domain_t
enum type_encoding_t {
    T_UNINIT = -7,
    T_MAP_PROGRAMS = -6,
    T_MAP = -5,
    T_NUM = -4,
    T_CTX = -3,
    T_PACKET = -2,
    T_STACK = -1,
    T_SHARED = 0
};

constexpr type_encoding_t T_MIN = T_MAP_PROGRAMS;
constexpr type_encoding_t T_MAX = T_SHARED;

std::vector<type_encoding_t> iterate_types(type_encoding_t lb, type_encoding_t ub);

std::string type_encoding_to_string(type_encoding_t s);
type_encoding_t string_to_type_encoding(const std::string& s);

} // namespace crab

enum class TypeGroup {
    number,
    map_fd,
    ctx,             ///< pointer to the special memory region named 'ctx'
    packet,          ///< pointer to the packet
    stack,           ///< pointer to the stack
    shared,          ///< pointer to shared memory
    map_fd_programs, ///< reg == T_MAP_PROGRAMS
    non_map_fd,      ///< reg >= T_NUM
    mem,             ///< shared | stack | packet = reg >= T_PACKET
    mem_or_num,      ///< reg >= T_NUM && reg != T_CTX
    pointer,         ///< reg >= T_CTX
    ptr_or_num,      ///< reg >= T_NUM
    stack_or_packet, ///< reg <= T_STACK && reg >= T_PACKET
    singleton_ptr,   ///< reg <= T_STACK && reg >= T_CTX
};

std::string to_string(TypeGroup ts);
inline std::ostream& operator<<(std::ostream& os, const TypeGroup ts) { return os << to_string(ts); }
