#pragma once

#include <crab/config.h>
#include <crab/common/types.hpp>
#include <crab/common/debug.hpp>
#include <crab/cfg/cfg.hpp>
#include <crab/cfg/cfg_bgl.hpp>
#include <crab/cg/cg.hpp>
#include <crab/cg/cg_bgl.hpp> 
#include <crab/cfg/var_factory.hpp>

#include <crab/domains/linear_constraints.hpp> 
#include <crab/domains/intervals.hpp>
#include <crab/domains/dis_intervals.hpp>
#include <crab/domains/wrapped_interval_domain.hpp>
#include <crab/domains/sparse_dbm.hpp>                      
#include <crab/domains/split_dbm.hpp>
#include <crab/domains/boxes.hpp>                      
#include <crab/domains/apron_domains.hpp>                      
#include <crab/domains/term_equiv.hpp>
#include <crab/domains/array_sparse_graph.hpp>                      
#include <crab/domains/array_smashing.hpp>
#include <crab/domains/array_expansion.hpp>
#include <crab/domains/nullity.hpp>
#include <crab/domains/flat_boolean_domain.hpp>                      
#include <crab/domains/combined_domains.hpp>                      
#include <crab/domains/array_sparse_graph.hpp>

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
  
  namespace cg_impl {
    /// To define CG over integers
    typedef cg::call_graph<cfg_impl::z_cfg_ref_t> z_cg_t;
    typedef cg::call_graph_ref<z_cg_t> z_cg_ref_t;
  }

  namespace domain_impl {
    
    using namespace crab::cfg_impl;
    using namespace crab::domains; 

    typedef pointer_constraint<ikos::variable<z_number, varname_t> > z_ptr_cst_t;
    typedef linear_constraint_system<ikos::z_number, varname_t> z_lin_cst_sys_t;
    typedef interval<ikos::z_number> z_interval_t;
    
    // Numerical domains over integers
    using z_interval_domain_t = interval_domain<ikos::z_number,varname_t>;
    using z_ric_domain_t = numerical_congruence_domain<z_interval_domain_t>;
    using z_dbm_domain_t = SparseDBM<ikos::z_number,varname_t,SpDBM_impl::DefaultParams<ikos::z_number,SpDBM_impl::GraphRep::adapt_ss>>;
    using z_sdbm_domain_t = SplitDBM<ikos::z_number,varname_t,SDBM_impl::DefaultParams<ikos::z_number, SDBM_impl::GraphRep::adapt_ss>>;
    using z_boxes_domain_t = boxes_domain<ikos::z_number,varname_t>;
    using z_dis_interval_domain_t = dis_interval_domain<ikos::z_number, varname_t >;
    using z_box_apron_domain_t = apron_domain<ikos::z_number,varname_t,apron_domain_id_t::APRON_INT>;
    using z_oct_apron_domain_t = apron_domain<ikos::z_number,varname_t,apron_domain_id_t::APRON_OCT>;
    using z_opt_oct_apron_domain_t = apron_domain<ikos::z_number,varname_t,apron_domain_id_t::APRON_OPT_OCT>;
    using z_pk_apron_domain_t = apron_domain<ikos::z_number,varname_t,apron_domain_id_t::APRON_PK>;
    using z_term_domain_t = term_domain<term::TDomInfo<ikos::z_number,varname_t,z_interval_domain_t> >;
    using z_term_dbm_t = term_domain<term::TDomInfo<ikos::z_number,varname_t,z_sdbm_domain_t> >;
    using z_term_dis_int_t = term_domain<term::TDomInfo<ikos::z_number,varname_t,z_dis_interval_domain_t> >;
    using z_num_domain_t = reduced_numerical_domain_product2<z_term_dis_int_t,z_sdbm_domain_t>;
    using z_num_boxes_domain_t = reduced_numerical_domain_product2<z_boxes_domain_t,z_sdbm_domain_t>;

    // Pointer domains over integers
    typedef nullity_domain<ikos::z_number, varname_t> z_nullity_domain_t;
    // Numerical x pointer domains over integers
    typedef numerical_nullity_domain<z_sdbm_domain_t> z_num_null_domain_t;
    // Boolean-numerical domain over integers
    typedef flat_boolean_numerical_domain<z_dbm_domain_t> z_bool_num_domain_t;
    typedef flat_boolean_numerical_domain<z_interval_domain_t> z_bool_interval_domain_t;    
    // Arrays domains
    typedef array_sparse_graph_domain<z_sdbm_domain_t,z_interval_domain_t> z_ag_sdbm_intv_t;
    typedef array_sparse_graph_domain<z_num_null_domain_t,z_nullity_domain_t> z_ag_num_null_t;
    typedef array_smashing<z_dis_interval_domain_t> z_as_dis_int_t;
    typedef array_smashing<z_sdbm_domain_t> z_as_sdbm_t;
    typedef array_smashing<z_num_null_domain_t> z_as_num_null_t;
    typedef array_smashing<z_bool_num_domain_t> z_as_bool_num_t;
    typedef array_expansion_domain<z_term_domain_t> z_ae_term_int_t;
    // machine arithmetic domains
    using z_wrapped_interval_domain_t = wrapped_interval_domain<ikos::z_number, varname_t>;
  } 
}
