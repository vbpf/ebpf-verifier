#pragma once

#include <string>
#include <vector>
#include <map>
#include <tuple>

#include "spec_type_descriptors.hpp"

#include "asm_cfg.hpp"

/** Run the analysis using crab.
 * 
 * \return A pair (passed, number_of_seconds)
 * 
 */
std::tuple<bool, double> abs_validate(Cfg const& simple_cfg, std::string domain_name, program_info info);

/** A mapping from available abstract domains to their description.
 * 
 */
std::map<std::string, std::string> domain_descriptions();

int create_map_crab(uint32_t map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries);