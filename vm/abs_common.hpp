#ifndef ABS_COMMON_HPP
#define ABS_COMMON_HPP

#include <crab/config.h>
#include <crab/common/types.hpp>
#include <crab/common/debug.hpp>
#include <crab/cfg/cfg.hpp>
#include <crab/cfg/cfg_bgl.hpp>
#include <crab/cg/cg.hpp>
#include <crab/cg/cg_bgl.hpp> 
#include <crab/cfg/var_factory.hpp>


namespace crab {

  namespace cfg_impl {

    /// BEGIN MUST BE DEFINED BY CRAB CLIENT
    // A variable factory based on strings
    using variable_factory_t = cfg::var_factory_impl::str_variable_factory;
    using varname_t = typename variable_factory_t::varname_t;
    using basic_block_label_t = std::string;
    template<> inline std::string get_label_str(basic_block_label_t e) { return e; }
    /// END MUST BE DEFINED BY CRAB CLIENT    

  }
}

using crab::cfg_impl::varname_t;
using crab::cfg_impl::basic_block_label_t;
using ikos::z_number;

/// CFG over integers
using cfg_t         = crab::cfg::Cfg<basic_block_label_t, varname_t, z_number>;
using basic_block_t = cfg_t::basic_block_t;
#endif
