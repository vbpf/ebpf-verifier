#pragma once

#include "asm_syntax.hpp"
#include "spec_assertions.hpp"

/** Analyze a program using the home-brewed version of Reduced Cardinal Power.
 *
 * Removes safe assertions in-place.
 */
void analyze_rcp(Cfg &cfg, program_info info);
int create_map_rcp(uint32_t map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries);
