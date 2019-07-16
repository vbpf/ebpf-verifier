#pragma once

#include "crab/cfg.hpp"
#include "crab/debug.hpp"
#include "crab/types.hpp"

using crab::number_t;
using crab::varname_t;

using crab::variable_factory;

/// CFG over integers
using cfg_t = crab::cfg<basic_block_label_t, varname_t, number_t>;
using basic_block_t = cfg_t::basic_block_t;
