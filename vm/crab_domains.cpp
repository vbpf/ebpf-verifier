#include "crab_dom.hpp"

using namespace crab::domain_impl;
using namespace crab::cfg_impl;
using namespace crab::domains;

template class interval_domain<ikos::z_number,varname_t>;
template class numerical_congruence_domain<z_interval_domain_t>;
template class term_domain<term::TDomInfo<ikos::z_number,varname_t,z_interval_domain_t> >;
template class term_domain<term::TDomInfo<ikos::z_number,varname_t,z_sdbm_domain_t> >;
template class term_domain<term::TDomInfo<ikos::z_number,varname_t,z_dis_interval_domain_t> >;
template class reduced_numerical_domain_product2<z_term_dis_int_t,z_sdbm_domain_t>;
template class dis_interval_domain<ikos::z_number, varname_t >;

/*
template class boxes_domain_<ikos::z_number,varname_t, -1, 3000UL>;
template class SparseDBM_<ikos::z_number,varname_t,SpDBM_impl::DefaultParams<ikos::z_number, SpDBM_impl::GraphRep::adapt_ss>>;
template class SplitDBM_<ikos::z_number,varname_t,SDBM_impl::DefaultParams<ikos::z_number, SDBM_impl::GraphRep::adapt_ss>>;
template class apron_domain_<ikos::z_number,varname_t,apron_domain_id_t::APRON_INT>;
template class apron_domain_<ikos::z_number,varname_t,apron_domain_id_t::APRON_OCT>;
template class apron_domain_<ikos::z_number,varname_t,apron_domain_id_t::APRON_OPT_OCT>;
template class apron_domain_<ikos::z_number,varname_t,apron_domain_id_t::APRON_PK>;
*/
/*
z_interval_domain_t z_interval_domain;
z_ric_domain_t z_ric_domain;
z_dbm_domain_t z_dbm_domain;
z_sdbm_domain_t z_sdbm_domain;
z_boxes_domain_t z_boxes_domain;
z_dis_interval_domain_t z_dis_interval_domain;
z_box_apron_domain_t z_box_apron_domain;
z_oct_apron_domain_t z_oct_apron_domain;
z_opt_oct_apron_domain_t z_opt_oct_apron_domain;
z_pk_apron_domain_t z_pk_apron_domain;
z_term_domain_t z_term_domain;
z_term_dbm_t z_term_dbm;
z_term_dis_int_t z_term_dis_int;
z_num_domain_t z_num_domain;
*/