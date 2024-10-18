// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <map>

#include "crab/cfg.hpp"
#include "crab/ebpf_domain.hpp"

namespace crab {

using invariant_table_t = std::map<label_t, ebpf_domain_t>;

std::pair<invariant_table_t, invariant_table_t> run_forward_analyzer(const cfg_t& cfg, ebpf_domain_t entry_inv);

} // namespace crab
