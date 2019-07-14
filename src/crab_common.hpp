#pragma once

#include "crab/types.hpp"
#include "crab/debug.hpp"
#include "crab/cfg.hpp"
#include "crab/cfg_bgl.hpp"
#include "crab/var_factory.hpp"

using crab::varname_t;
using crab::number_t;

using crab::variable_factory;

/// CFG over integers
using cfg_t         = crab::cfg<basic_block_label_t, varname_t, number_t>;
using basic_block_t = cfg_t::basic_block_t;
using lin_exp_t = ikos::linear_expression<number_t, varname_t>;
