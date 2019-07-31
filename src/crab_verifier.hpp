#pragma once

#include <tuple>

#include "spec_type_descriptors.hpp"
#include "crab/cfg.hpp"

std::tuple<bool, double> abs_validate(cfg_t& cfg, program_info info);

int create_map_crab(uint32_t map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries);
