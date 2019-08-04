#pragma once

#include <unordered_map>
#include <tuple>

#include "crab/cfg.hpp"
#include "crab/ebpf_domain.hpp"

namespace crab {

using domains::ebpf_domain_t;
using invariant_table_t = std::unordered_map<label_t, ebpf_domain_t>;

std::pair<invariant_table_t, invariant_table_t> run_forward_analyzer(cfg_t& cfg);

} // namespace crab
