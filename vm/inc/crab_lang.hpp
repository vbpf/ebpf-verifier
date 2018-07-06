#ifndef __CRAB_LANGUAGE__
#define __CRAB_LANGUAGE__

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
    typedef cfg::var_factory_impl::str_variable_factory variable_factory_t;
    typedef typename variable_factory_t::varname_t varname_t;

    // CFG basic block labels
    typedef std::string basic_block_label_t;
    template<> inline std::string get_label_str(std::string e) 
    { return e; }
    /// END MUST BE DEFINED BY CRAB CLIENT    


    /// To define CFG over integers
    typedef cfg::Cfg<basic_block_label_t, varname_t, ikos::z_number> z_cfg_t;
    typedef cfg::cfg_ref<z_cfg_t> z_cfg_ref_t;
    typedef cfg::cfg_rev<z_cfg_ref_t> z_cfg_rev_t;
    typedef z_cfg_t::basic_block_t z_basic_block_t;
    typedef ikos::variable<ikos::z_number, varname_t> z_var;
    typedef ikos::linear_expression<ikos::z_number, varname_t> z_lin_t;
    typedef ikos::linear_constraint<ikos::z_number, varname_t> z_lin_cst_t;
    
    /// To define CFG over rationals    
    typedef cfg::Cfg<basic_block_label_t, varname_t, ikos::q_number> q_cfg_t;
    typedef cfg::cfg_ref<q_cfg_t> q_cfg_ref_t;
    typedef cfg::cfg_rev<q_cfg_ref_t> q_cfg_rev_t;
    typedef q_cfg_t::basic_block_t q_basic_block_t;    
    typedef ikos::variable<ikos::q_number, varname_t> q_var;
    typedef ikos::linear_expression<ikos::q_number, varname_t> q_lin_t;
    typedef ikos::linear_constraint<ikos::q_number, varname_t> q_lin_cst_t;
  }
  
  namespace cg_impl {
    /// To define CG over integers
    typedef cg::call_graph<cfg_impl::z_cfg_ref_t> z_cg_t;
    typedef cg::call_graph_ref<z_cg_t> z_cg_ref_t;
  }
  
} // end namespace
#endif  /*__CRAB_LANGUAGE__*/
