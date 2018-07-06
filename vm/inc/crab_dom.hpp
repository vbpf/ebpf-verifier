#ifndef __CRAB_DOMAINS__
#define __CRAB_DOMAINS__

#include "./crab_lang.hpp"

#include <crab/domains/linear_constraints.hpp> 
#include <crab/domains/intervals.hpp>
#include <crab/domains/wrapped_interval_domain.hpp>
#include <crab/domains/sparse_dbm.hpp>                      
#include <crab/domains/split_dbm.hpp>
#include <crab/domains/boxes.hpp>                      
#include <crab/domains/apron_domains.hpp>                      
#include <crab/domains/dis_intervals.hpp>
#include <crab/domains/term_equiv.hpp>
#include <crab/domains/array_sparse_graph.hpp>                      
#include <crab/domains/array_smashing.hpp>
#include <crab/domains/nullity.hpp>
#include <crab/domains/flat_boolean_domain.hpp>                      
#include <crab/domains/combined_domains.hpp>                      

namespace crab {

  namespace domain_impl {
    
    using namespace crab::cfg_impl;
    using namespace crab::domains; 

    typedef pointer_constraint<ikos::variable<z_number, varname_t> > z_ptr_cst_t;
    typedef linear_constraint_system<ikos::z_number, varname_t> z_lin_cst_sys_t;
    typedef linear_constraint_system<ikos::q_number, varname_t> q_lin_cst_sys_t;
    typedef interval<ikos::z_number> z_interval_t;
    typedef interval<ikos::q_number> q_interval_t;
    
    // Numerical domains over integers
    typedef interval_domain<ikos::z_number,varname_t> z_interval_domain_t;
    typedef numerical_congruence_domain<z_interval_domain_t> z_ric_domain_t;
    typedef SpDBM_impl::DefaultParams<ikos::z_number,SpDBM_impl::GraphRep::adapt_ss> z_SparseDBMGraph;
    typedef SparseDBM<ikos::z_number,varname_t,z_SparseDBMGraph> z_dbm_domain_t;
    typedef SDBM_impl::DefaultParams<ikos::z_number, SDBM_impl::GraphRep::adapt_ss> z_SplitDBMGraph;
    typedef SplitDBM<ikos::z_number,varname_t,z_SplitDBMGraph> z_sdbm_domain_t;
    typedef boxes_domain<ikos::z_number,varname_t> z_boxes_domain_t;
    typedef dis_interval_domain<ikos::z_number, varname_t > z_dis_interval_domain_t;
    typedef apron_domain<ikos::z_number,varname_t,apron_domain_id_t::APRON_INT> z_box_apron_domain_t;
    typedef apron_domain<ikos::z_number,varname_t,apron_domain_id_t::APRON_OCT> z_oct_apron_domain_t;
    typedef apron_domain<ikos::z_number,varname_t,apron_domain_id_t::APRON_OPT_OCT> z_opt_oct_apron_domain_t;
    typedef apron_domain<ikos::z_number,varname_t,apron_domain_id_t::APRON_PK> z_pk_apron_domain_t;
    typedef term_domain<term::TDomInfo<ikos::z_number,varname_t,z_interval_domain_t> > z_term_domain_t;
    typedef term_domain<term::TDomInfo<ikos::z_number,varname_t,z_sdbm_domain_t> > z_term_dbm_t;
    typedef term_domain<term::TDomInfo<ikos::z_number,varname_t,z_dis_interval_domain_t> > z_term_dis_int_t;
    typedef reduced_numerical_domain_product2<z_term_dis_int_t,z_sdbm_domain_t> z_num_domain_t;
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
    // machine arithmetic domains
    typedef wrapped_interval_domain<ikos::z_number, varname_t> z_wrapped_interval_domain_t;
    /// Numerical domains over rationals
    typedef interval_domain<ikos::q_number,varname_t > q_interval_domain_t;
    typedef apron_domain<ikos::q_number,varname_t,apron_domain_id_t::APRON_PK>
    q_pk_apron_domain_t;
    typedef boxes_domain<q_number, varname_t > q_boxes_domain_t;         
  } 
}
#endif /*__CRAB_DOMAINS__*/
