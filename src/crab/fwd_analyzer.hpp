// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <map>
#include <tuple>

#include "config.hpp"
#include "crab/cfg.hpp"
#include "crab/ebpf_domain.hpp"

namespace crab {

using domains::ebpf_domain_t;
using invariant_table_t = std::map<label_t, ebpf_domain_t>;

std::pair<invariant_table_t, invariant_table_t> run_forward_analyzer(cfg_t& cfg, program_info& info, bool check_termination);

} // namespace crab
