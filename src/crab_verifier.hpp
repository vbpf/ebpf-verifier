// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "config.hpp"
#include "crab/cfg.hpp"
#include "spec_type_descriptors.hpp"
#include "string_constraints.hpp"

bool run_ebpf_analysis(std::ostream& s, const cfg_t& cfg, const program_info& info,
                       const ebpf_verifier_options_t& options, ebpf_verifier_stats_t* stats);

bool ebpf_verify_program(std::ostream& os, const InstructionSeq& prog, const program_info& info,
                         const ebpf_verifier_options_t& options, ebpf_verifier_stats_t* stats);

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
 * These constraints represent the program state at a specific point in the control flow graph,
 * as determined by the static analysis performed by the verifier.
 *
 * If the 'store_pre_invariants' option is not set, this function will always return false along with an error message.
 * This is because the verifier did not store the abstract constraints at each label.
 *
 * For invalid labels, this function will return false along with an error message.
 *
 * @param[in,out] os Print output to this stream.
 * @param[in] label The location in the CFG to check against.
 * @param[in] constraints The concrete state to check.
 * @retval true The state is valid.
 * @retval false The state is invalid.
 *
 * Note:
 * This can also return false if the label is not found in the CFG or if the label is malformed.
 */
bool ebpf_check_constraints_at_label(std::ostream& os, const std::string& label,
                                     const std::set<std::string>& constraints);
/**
 * @brief Get the invariants at a given label. Requires the `store_pre_invariants` option to be set.
 *
 * If the 'store_pre_invariants' option is not set, this function will return an empty set
 * as no invariants were stored during verification.
 *
 * @param[in] label The label in the CFG where invariants should be retrieved
 * @return The set of invariants at the given label.
 *         Each invariant represents a constraint on the program state at this point.
 *         Returns an empty set if no invariants are available.
 * @throw std::invalid_argument The label format is invalid
 * @throw std::out_of_range The label value causes numeric overflow
 */
std::set<std::string> ebpf_get_invariants_at_label(const std::string& label);
