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
