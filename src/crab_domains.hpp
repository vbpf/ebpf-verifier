#pragma once
                  
#include "crab/split_dbm.hpp"
#include "crab/array_expansion.hpp"

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
    typedef cfg::cfg<basic_block_label_t, varname_t, ikos::z_number> z_cfg_t;
    typedef cfg::cfg_ref<z_cfg_t> z_cfg_ref_t;
    typedef cfg::cfg_rev<z_cfg_ref_t> z_cfg_rev_t;
    typedef z_cfg_t::basic_block_t z_basic_block_t;
    typedef ikos::variable<ikos::z_number, varname_t> z_var;
    typedef ikos::linear_expression<ikos::z_number, varname_t> z_lin_t;
    typedef ikos::linear_constraint<ikos::z_number, varname_t> z_lin_cst_t;
  }

  namespace domain_impl {
    
    using namespace crab::cfg_impl;
    using namespace crab::domains; 

    typedef pointer_constraint<ikos::variable<z_number, varname_t> > z_ptr_cst_t;
    typedef linear_constraint_system<ikos::z_number, varname_t> z_lin_cst_sys_t;
    typedef interval<ikos::z_number> z_interval_t;
    
    // Numerical domains over integers
    using SafeInt = DBM_impl::SafeInt64DefaultParams<ikos::z_number, DBM_impl::GraphRep::adapt_ss>;
    using z_sdbm_domain_t = SplitDBM<ikos::z_number,varname_t,SafeInt>;
  } 
}
