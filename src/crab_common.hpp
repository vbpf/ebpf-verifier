#pragma once

#include "crab/types.hpp"
#include "crab/debug.hpp"
#include "crab/cfg.hpp"
#include "crab/cfg_bgl.hpp"
#include "crab/var_factory.hpp"


namespace crab {

  namespace cfg_impl {

    /// BEGIN MUST BE DEFINED BY CRAB CLIENT
    // A variable factory based on strings
    using variable_factory_t = cfg::var_factory_impl::str_variable_factory;
    using varname_t = typename variable_factory_t::varname_t;
    using basic_block_label_t = std::string;
    //template<> inline std::string get_label_str(std::string e) { return e; }
    /// END MUST BE DEFINED BY CRAB CLIENT    

  }
}

using crab::cfg_impl::varname_t;
using crab::cfg_impl::basic_block_label_t;
using crab::cfg_impl::variable_factory_t;

/// CFG over integers
using cfg_t         = crab::cfg::cfg<basic_block_label_t, varname_t, ikos::z_number>;
using basic_block_t = cfg_t::basic_block_t;
using lin_exp_t = ikos::linear_expression<ikos::z_number, varname_t>;
