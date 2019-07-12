#pragma once

#include "crab/types.hpp"
#include "crab/debug.hpp"
#include "crab/cfg.hpp"
#include "crab/cfg_bgl.hpp"
#include "crab/var_factory.hpp"

using crab::varname_t;
using crab::cfg::variable_factory;

/// CFG over integers
using cfg_t         = crab::cfg::cfg<basic_block_label_t, varname_t, ikos::z_number>;
using basic_block_t = cfg_t::basic_block_t;
using lin_exp_t = ikos::linear_expression<ikos::z_number, varname_t>;
