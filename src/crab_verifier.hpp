// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "config.hpp"
#include "crab/cfg.hpp"
#include "spec_type_descriptors.hpp"
#include "string_constraints.hpp"

bool run_ebpf_analysis(std::ostream& s, cfg_t& cfg, const program_info& info, const ebpf_verifier_options_t* options,
                       ebpf_verifier_stats_t* stats);

bool ebpf_verify_program(std::ostream& os, const InstructionSeq& prog, const program_info& info,
                         const ebpf_verifier_options_t* options, ebpf_verifier_stats_t* stats);

using string_invariant_map = std::map<label_t, string_invariant>;

std::tuple<string_invariant, bool> ebpf_analyze_program_for_test(std::ostream& os, const InstructionSeq& prog,
                                                                 const string_invariant& entry_invariant,
                                                                 const program_info& info,
                                                                 const ebpf_verifier_options_t& options);

int create_map_crab(const EbpfMapType& map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries,
                    ebpf_verifier_options_t options);

EbpfMapDescriptor* find_map_descriptor(int map_fd);

void ebpf_verifier_clear_thread_local_state();

/**
 * @brief Given a label and a set of concrete constraints, check if the concrete constraints match the abstract
 * verifier constraints at the label. Requires the `store_pre_invariants` option to be set.
 *
 * Abstract constraints are computed by the verifier and stored if the `store_pre_invariants` option is set.
 *
 * @param[in,out] os Print output to this stream.
 * @param[in] label The location in the CFG to check against.
 * @param[in] constraints The concrete state to check.
 * @return true If the state is valid.
 * @return false If the state is invalid.
 */
bool ebpf_check_constraints_at_label(std::ostream& os, const std::string& label,
                                     const std::set<std::string>& constraints);
/**
 * @brief Get the invariants at a given label. Requires the `store_pre_invariants` option to be set.
 *
 * @param[in] label
 * @return The set of invariants at the given label.
 * @throw std::out_of_range If the label is not found.
 */
std::set<std::string> ebpf_get_invariants_at_label(const std::string& label);
