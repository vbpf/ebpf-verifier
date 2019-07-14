#pragma once

#include "crab/split_dbm.hpp"
#include "crab/array_expansion.hpp"

namespace crab {

    /// BEGIN MUST BE DEFINED BY CRAB CLIENT
    // A variable factory based on strings

    template<> inline std::string get_label_str(std::string e)  { return e; }
    /// END MUST BE DEFINED BY CRAB CLIENT


    /// To define CFG over integers
    using z_cfg_t = cfg<basic_block_label_t, varname_t, ikos::z_number>;
    using z_cfg_ref_t = cfg_ref<z_cfg_t>;
    using z_cfg_rev_t = cfg_rev<z_cfg_ref_t>;
    using z_basic_block_t = z_cfg_t::basic_block_t;
    using z_var = ikos::variable<ikos::z_number, varname_t>;
    using z_lin_t = ikos::linear_expression<ikos::z_number, varname_t>;
    using z_lin_cst_t = ikos::linear_constraint<ikos::z_number, varname_t>;

  namespace domain_impl {

    using namespace crab::domains;

    using z_lin_cst_sys_t = linear_constraint_system<ikos::z_number, varname_t>;
    using z_interval_t = interval<ikos::z_number>;

    // Numerical domains over integers
    using SafeInt = DBM_impl::SafeInt64DefaultParams;
    using z_sdbm_domain_t = SplitDBM<ikos::z_number,varname_t,SafeInt>;
  }
}
