// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "crab/fwd_analyzer.hpp"
#include "crab/array_domain.hpp"
#include "crab/variable.hpp"

namespace crab {

// This class holds "global" state for a verifier run.
class crab_verifier_job_t final {
    crab::domains::array_map_t _array_map;
    const program_info& _program_info;
    interleaved_fwd_fixpoint_iterator_t _analyzer;

  public:
    crab_verifier_job_t(cfg_t& cfg, program_info& info, unsigned int max_instruction_count, bool check_termination)
        : _program_info(info), _analyzer(cfg, this, max_instruction_count, check_termination) {}

    interleaved_fwd_fixpoint_iterator_t& analyzer() { return _analyzer; }
    const program_info& get_program_info() const { return _program_info; }

    crab::domains::offset_map_t& lookup_array_map(data_kind_t kind) { return _array_map[kind]; }
};

} // namespace crab