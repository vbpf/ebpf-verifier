#pragma once

/* 
   User-definable assertion checker
 */

#include "crab/types.hpp"
#include "crab/base_property.hpp"
#include "crab/abstract_domain_specialized_traits.hpp"

namespace crab
{

namespace checker
{

template <typename Analyzer>
class assert_property_checker : public property_checker<Analyzer>
{

	typedef typename Analyzer::varname_t varname_t;
	typedef typename Analyzer::number_t number_t;

	typedef ikos::interval<number_t> interval_t;
	typedef typename Analyzer::abs_dom_t abs_dom_t;
	typedef property_checker<Analyzer> base_checker_t;

	using typename base_checker_t::assert_t;
	using typename base_checker_t::assign_t;
	using typename base_checker_t::assume_t;
	using typename base_checker_t::basic_block_t;
	using typename base_checker_t::bin_op_t;
	using typename base_checker_t::lin_cst_sys_t;
	using typename base_checker_t::lin_cst_t;
	using typename base_checker_t::lin_exp_t;
	using typename base_checker_t::var_t;

public:
	assert_property_checker(int verbose = 0) : base_checker_t(verbose) {}

	virtual std::string get_property_name() const override
	{
		return "user-defined assertion checker using " +
			   abs_dom_t::getDomainName();
	}

	virtual bool is_interesting(const basic_block_t &bb) const override
	{
		for (auto &s : bb)
		{
			if (s.is_assert())
			{
				return true;
			}
		}
		return false;
	}

	virtual void check(assert_t &s) override
	{
		if (!this->m_abs_tr)
			return;

		lin_cst_t cst = s.constraint();

		if (this->m_safe_assertions.count(&s) > 0)
		{
			crab::crab_string_os os;
			if (this->m_verbose >= 3)
			{
				os << "Property : " << cst << "\n";
				os << "Invariant: " << *(this->m_abs_tr->get()) << "\n";
				os << "Note: it was proven by the forward+backward analysis";
			}
			this->add_safe(os.str(), &s);
		}
		else
		{
			if (cst.is_contradiction())
			{
				if (this->m_abs_tr->get()->is_bottom())
				{
					crab::crab_string_os os;
					if (this->m_verbose >= 3)
					{
						os << "Property : " << cst << "\n";
						os << "Invariant: " << *(this->m_abs_tr->get());
					}
					this->add_safe(os.str(), &s);
				}
				else
				{
					crab::crab_string_os os;
					if (this->m_verbose >= 2)
					{
						os << "Property : " << cst << "\n";
						os << "Invariant: " << *(this->m_abs_tr->get());
					}
					this->add_warning(os.str(), &s);
				}
				return;
			}

			if (this->m_abs_tr->get()->is_bottom())
			{
				this->m_db.add(_UNREACH);
				return;
			}

			abs_dom_t inv(*(this->m_abs_tr->get()));
			if (crab::domains::checker_domain_traits<abs_dom_t>::entail(inv, cst))
			{
				crab::crab_string_os os;
				if (this->m_verbose >= 3)
				{
					os << "Property : " << cst << "\n";
					os << "Invariant: " << inv;
				}
				this->add_safe(os.str(), &s);
			}
			else if (crab::domains::checker_domain_traits<abs_dom_t>::intersect(inv, cst))
			{
				crab::crab_string_os os;
				if (this->m_verbose >= 2)
				{
					os << "Property : " << cst << "\n";
					os << "Invariant: " << inv;
				}
				this->add_warning(os.str(), &s);
			}
			else
			{
				/* Instead this program:
		 x:=0; 
		 y:=1;
		 if (x=34) {
                   assert(y==2);
                 }
                 Suppose due to some abstraction we have:
                  havoc(x); 
	          y:=1;
                  if (x=34) {
                    assert(y==2);
                  }
		 As a result, we have inv={y=1,x=34}  and cst={y=2}
		 Note that inv does not either entail or intersect with cst.
		 However, the original program does not violate the assertion.
	      */
				crab::crab_string_os os;
				if (this->m_verbose >= 2)
				{
					os << "Property : " << cst << "\n";
					os << "Invariant: " << inv;
				}
				this->add_warning(os.str(), &s);
			}
		}
		s.accept(&*this->m_abs_tr); // propagate invariants to the next stmt
	}

};
} // namespace checker
} // namespace crab
