#include "crab_dom.hpp"

using namespace crab::domain_impl;
using namespace crab::cfg_impl;
using namespace crab::domains;

namespace ikos {
template class interval_domain<z_number,varname_t>;
}

namespace crab::domains {
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
}
