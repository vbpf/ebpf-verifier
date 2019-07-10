/*******************************************************************************
 *
 * The interleaved fixpoint iterator is described in G. Amato and F. Scozzari's
 * paper: Localizing widening and narrowing. In Proceedings of SAS 2013,
 * pages 25-42. LNCS 7935, 2013.
 *
 * Author: Arnaud J. Venet (arnaud.j.venet@nasa.gov)
 * Contributors: Jorge A. Navas (jorge.navas@sri.com)
 *
 * Notices:
 *
 * Copyright (c) 2011 United States Government as represented by the
 * Administrator of the National Aeronautics and Space Administration.
 * All Rights Reserved.
 *
 * Disclaimers:
 *
 * No Warranty: THE SUBJECT SOFTWARE IS PROVIDED "AS IS" WITHOUT ANY WARRANTY OF
 * ANY KIND, EITHER EXPRESSED, IMPLIED, OR STATUTORY, INCLUDING, BUT NOT LIMITED
 * TO, ANY WARRANTY THAT THE SUBJECT SOFTWARE WILL CONFORM TO SPECIFICATIONS,
 * ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE,
 * OR FREEDOM FROM INFRINGEMENT, ANY WARRANTY THAT THE SUBJECT SOFTWARE WILL BE
 * ERROR FREE, OR ANY WARRANTY THAT DOCUMENTATION, IF PROVIDED, WILL CONFORM TO
 * THE SUBJECT SOFTWARE. THIS AGREEMENT DOES NOT, IN ANY MANNER, CONSTITUTE AN
 * ENDORSEMENT BY GOVERNMENT AGENCY OR ANY PRIOR RECIPIENT OF ANY RESULTS,
 * RESULTING DESIGNS, HARDWARE, SOFTWARE PRODUCTS OR ANY OTHER APPLICATIONS
 * RESULTING FROM USE OF THE SUBJECT SOFTWARE.  FURTHER, GOVERNMENT AGENCY
 * DISCLAIMS ALL WARRANTIES AND LIABILITIES REGARDING THIRD-PARTY SOFTWARE,
 * IF PRESENT IN THE ORIGINAL SOFTWARE, AND DISTRIBUTES IT "AS IS."
 *
 * Waiver and Indemnity:  RECIPIENT AGREES TO WAIVE ANY AND ALL CLAIMS AGAINST
 * THE UNITED STATES GOVERNMENT, ITS CONTRACTORS AND SUBCONTRACTORS, AS WELL
 * AS ANY PRIOR RECIPIENT.  IF RECIPIENT'S USE OF THE SUBJECT SOFTWARE RESULTS
 * IN ANY LIABILITIES, DEMANDS, DAMAGES, EXPENSES OR LOSSES ARISING FROM SUCH
 * USE, INCLUDING ANY DAMAGES FROM PRODUCTS BASED ON, OR RESULTING FROM,
 * RECIPIENT'S USE OF THE SUBJECT SOFTWARE, RECIPIENT SHALL INDEMNIFY AND HOLD
 * HARMLESS THE UNITED STATES GOVERNMENT, ITS CONTRACTORS AND SUBCONTRACTORS,
 * AS WELL AS ANY PRIOR RECIPIENT, TO THE EXTENT PERMITTED BY LAW.
 * RECIPIENT'S SOLE REMEDY FOR ANY SUCH MATTER SHALL BE THE IMMEDIATE,
 * UNILATERAL TERMINATION OF THIS AGREEMENT.
 *
 ******************************************************************************/

#pragma once

#include <boost/shared_ptr.hpp>
#include <boost/unordered_map.hpp>

#include "crab/types.hpp"
#include "crab/debug.hpp"
#include "crab/stats.hpp"
#include "crab/cfg_bgl.hpp"  // needed by wto
#include "crab/wto.hpp"
#include "crab/fixpoint_iterators_api.hpp"
#include "crab/thresholds.hpp"

namespace ikos {

  namespace interleaved_fwd_fixpoint_iterator_impl {

    template<typename CFG, typename AbstractValue>
    class wto_iterator;

    template<typename CFG, typename AbstractValue>
    class wto_processor;

  } // namespace interleaved_fwd_fixpoint_iterator_impl


  template<typename CFG, typename AbstractValue>
  class interleaved_fwd_fixpoint_iterator:
      public fixpoint_iterator<CFG, AbstractValue> {

    friend class interleaved_fwd_fixpoint_iterator_impl::wto_iterator<CFG, AbstractValue>;

  public:

    typedef typename CFG::basic_block_label_t basic_block_label_t;
    typedef wto<CFG> wto_t;
    typedef boost::unordered_map<basic_block_label_t,AbstractValue> assumption_map_t;
    typedef boost::unordered_map<basic_block_label_t,AbstractValue> invariant_table_t;

  private:

    typedef interleaved_fwd_fixpoint_iterator_impl::wto_iterator<CFG,AbstractValue> wto_iterator_t;
    typedef interleaved_fwd_fixpoint_iterator_impl::wto_processor<CFG,AbstractValue> wto_processor_t;
    typedef crab::iterators::thresholds<typename CFG::number_t> thresholds_t;
    typedef crab::iterators::wto_thresholds<CFG> wto_thresholds_t;

  protected:

    typedef typename invariant_table_t::iterator iterator;
    typedef typename invariant_table_t::const_iterator const_iterator;

    CFG _cfg;
    wto_t _wto;
    invariant_table_t _pre, _post;
    // number of iterations until triggering widening
    unsigned int _widening_delay;
    // number of narrowing iterations. If the narrowing operator is
    // indeed a narrowing operator this parameter is not
    // needed. However, there are abstract domains for which an actual
    // narrowing operation is not available so we must enforce
    // termination.
    unsigned int _descending_iterations;
    // whether jump set is used for widening
    bool _use_widening_jump_set;
    // set of thresholds to jump during widening
    typename wto_thresholds_t::thresholds_map_t _jump_set;
    // enable post-processing of the invariants
    bool _enable_processor;

  private:

    void set(invariant_table_t& table, basic_block_label_t node, const AbstractValue& v) {
      crab::CrabStats::count("Fixpo.invariant_table.update");
      crab::ScopedCrabStats __st__("Fixpo.invariant_table.update");

      std::pair<typename invariant_table_t::iterator, bool> res =
	table.emplace(std::make_pair(node, v));
      if (!res.second) {
        (res.first)->second = std::move(v);
      }
    }

    inline void set_pre(basic_block_label_t node, const AbstractValue& v) {
      this->set(this->_pre, node, v);
    }

    inline void set_post(basic_block_label_t node, const AbstractValue& v) {
      this->set(this->_post, node, v);
    }

    AbstractValue get(invariant_table_t& table, basic_block_label_t n) {
      crab::CrabStats::count("Fixpo.invariant_table.lookup");
      crab::ScopedCrabStats __st__("Fixpo.invariant_table.lookup");

      typename invariant_table_t::iterator it = table.find(n);
      if (it != table.end()) {
        return it->second;
      } else {
        return AbstractValue::bottom();
      }
    }

    AbstractValue extrapolate(basic_block_label_t node, unsigned int iteration,
                              AbstractValue before, AbstractValue after) {
      crab::CrabStats::count("Fixpo.extrapolate");
      crab::ScopedCrabStats __st__("Fixpo.extrapolate");

      CRAB_VERBOSE_IF(1, crab::get_msg_stream()
		      << "Widening " << iteration << " at "
		      << crab::cfg_impl::get_label_str(node) << "\n";);

      if (iteration <= _widening_delay) {
	auto widen_res = before | after;
        CRAB_VERBOSE_IF(3,
                 crab::outs() << "Prev   : " << before << "\n"
                              << "Current: " << after << "\n"
                              << "Res    : " << widen_res << "\n");
        return widen_res;
      } else {
        CRAB_VERBOSE_IF(3,
                 crab::outs() << "Prev   : " << before << "\n"
                              << "Current: " << after << "\n");

        if (_use_widening_jump_set) {
	  auto it = _jump_set.find(node);
	  if (it == _jump_set.end()) {
	    CRAB_ERROR("no thresholds found for ", crab::cfg_impl::get_label_str(node));
	  }
	  thresholds_t thresholds = it->second;
	  auto widen_res = before.widening_thresholds (after, thresholds);
          CRAB_VERBOSE_IF(3,
			  crab::outs() << "Res    : " << widen_res << "\n");
          return widen_res;
        } else {
	  auto widen_res = before || after;
          CRAB_VERBOSE_IF(3,
			  crab::outs() << "Res    : " << widen_res << "\n");
          return widen_res;
        }
      }
    }

    AbstractValue refine(basic_block_label_t node, unsigned int iteration,
                         AbstractValue before, AbstractValue after) {
      crab::CrabStats::count("Fixpo.refine");
      crab::ScopedCrabStats __st__("Fixpo.refine");

      CRAB_VERBOSE_IF(1,
		      crab::get_msg_stream() << "Decreasing iteration=" << iteration << "\n"
		      << "Narrowing at " << crab::cfg_impl::get_label_str(node) << "\n";);

      if (iteration == 1) {
	auto narrow_res = before & after;
        CRAB_VERBOSE_IF(3,
			crab::outs() << "Prev   : " << before << "\n"
			             << "Current: " << after << "\n"
                                     << "Res    : " << narrow_res << "\n");
        return narrow_res;
      } else {
	auto narrow_res = before && after;
        CRAB_VERBOSE_IF(3,
			crab::outs() << "Prev   : " << before << "\n"
			             << "Current: " << after << "\n"
                                     << "Res    : " << narrow_res << "\n");
        return narrow_res;
      }
    }

    void initialize_thresholds(size_t jump_set_size) {
      if (_use_widening_jump_set) {
        crab::CrabStats::resume("Fixpo");
        // select statically some widening points to jump to.
	wto_thresholds_t wto_thresholds(_cfg, jump_set_size);
	_wto.accept(&wto_thresholds);
	_jump_set = wto_thresholds.get_thresholds_map();
	CRAB_VERBOSE_IF(2, crab::outs () << "Thresholds\n" << wto_thresholds << "\n");
        crab::CrabStats::stop ("Fixpo");
      }
    }

  public:

    interleaved_fwd_fixpoint_iterator(CFG cfg, const wto_t *wto,
                                      unsigned int widening_delay,
                                      unsigned int descending_iterations,
                                      size_t jump_set_size,
				      bool enable_processor = true)
      : _cfg(cfg)
      , _wto(!wto ? cfg: *wto)
      , _widening_delay(widening_delay)
      , _descending_iterations(descending_iterations)
      , _use_widening_jump_set(jump_set_size > 0)
      , _enable_processor(enable_processor) {
      initialize_thresholds(jump_set_size);
    }

    virtual ~interleaved_fwd_fixpoint_iterator() { }

    CFG get_cfg() const {
      return this->_cfg;
    }

    const wto_t& get_wto() const {
      return this->_wto;
    }

    AbstractValue get_pre(basic_block_label_t node) {
      return this->get(this->_pre, node);
    }

    AbstractValue get_post(basic_block_label_t node) {
      return this->get(this->_post, node);
    }

    const invariant_table_t& get_pre_invariants() const {
      return this->_pre;
    }

    const invariant_table_t& get_post_invariants() const {
      return this->_post;
    }

    void run(AbstractValue init) {
      crab::ScopedCrabStats __st__("Fixpo");
      CRAB_VERBOSE_IF(1, crab::get_msg_stream() << "== Started fixpoint\n");
      this->set_pre(this->_cfg.entry(), init);
      wto_iterator_t iterator(this);
      this->_wto.accept(&iterator);
      if (_enable_processor) {
	wto_processor_t processor(this);
	this->_wto.accept(&processor);
      }
      CRAB_VERBOSE_IF(1, crab::get_msg_stream() << "== Fixpoint reached.\n");
      CRAB_VERBOSE_IF(2, crab::outs() << "Wto:\n" << _wto << "\n");
    }

    void run(basic_block_label_t entry, AbstractValue init,
	     const assumption_map_t &assumptions) {
      crab::ScopedCrabStats __st__("Fixpo");
      CRAB_VERBOSE_IF(1,
	     crab::get_msg_stream() << "== Started fixpoint at block "
		          << crab::cfg_impl::get_label_str(entry)
		          << " with initial value=" << init << "\n";);
      this->set_pre(entry, init);
      wto_iterator_t iterator(this, entry, &assumptions);
      this->_wto.accept(&iterator);
      if (_enable_processor) {
	wto_processor_t processor(this);
	this->_wto.accept(&processor);
      }
      CRAB_VERBOSE_IF(1, crab::get_msg_stream() << "== Fixpoint reached.\n");
      CRAB_VERBOSE_IF(2, crab::outs() << "Wto:\n" << _wto << "\n");

    }

    void clear() {
      this->_pre.clear();
      this->_post.clear();
    }

  }; // class interleaved_fwd_fixpoint_iterator

  namespace interleaved_fwd_fixpoint_iterator_impl {

    template<typename CFG, typename AbstractValue>
    class wto_iterator: public wto_component_visitor<CFG> {

    public:
      typedef interleaved_fwd_fixpoint_iterator<CFG, AbstractValue> interleaved_iterator_t;
      typedef wto_vertex<CFG> wto_vertex_t;
      typedef wto_cycle<CFG> wto_cycle_t;
      typedef wto<CFG> wto_t;
      typedef typename CFG::basic_block_label_t basic_block_label_t;
      typedef typename wto_t::wto_nesting_t wto_nesting_t;
      typedef typename interleaved_iterator_t::assumption_map_t assumption_map_t;

    private:
      interleaved_iterator_t *_iterator;
      // Initial entry point of the analysis
      basic_block_label_t _entry;
      const assumption_map_t *_assumptions;
      // Used to skip the analysis until _entry is found
      bool _skip;

      inline AbstractValue strengthen(basic_block_label_t n, AbstractValue inv) {
	crab::CrabStats::count("Fixpo.strengthen");
	crab::ScopedCrabStats __st__("Fixpo.strengthen");

	if (_assumptions) {
	  auto it = _assumptions->find(n);
	  if (it != _assumptions->end ()) {
	    CRAB_VERBOSE_IF(3,
			    crab::outs() << "Before assumption at " << n << ":"
			                 << inv << "\n");

	    inv = inv & it->second;
	    CRAB_VERBOSE_IF(3,
			    crab::outs() << "After assumption at " << n << ":"
			                 << inv << "\n");
	  }
	}
	return inv;
      }

      // Simple visitor to check if node is a member of the wto component.
      class member_component_visitor:
	public wto_component_visitor<CFG> {
	basic_block_label_t _node;
	bool _found;
      public:
	member_component_visitor(basic_block_label_t node): _node(node), _found(false) {}

	void visit(wto_vertex_t& c) {
	  if (!_found) { _found = (c.node() == _node); }
	}

	void visit(wto_cycle_t& c) {
	  if (!_found) {
	    _found = (c.head() == _node);
	    if (!_found) {
	      for(typename wto_cycle_t::iterator it = c.begin(), et = c.end(); it!=et; ++it) {
		if (_found) break;
		it->accept(this);
	      }
	    }
	  }
	}

	bool is_member() const { return _found;}
      };

    public:
      wto_iterator(interleaved_iterator_t *iterator)
	: _iterator(iterator),
	  _entry(_iterator->get_cfg().entry()),
	  _assumptions(nullptr),
	  _skip(true) { }

      wto_iterator(interleaved_iterator_t *iterator,
		   basic_block_label_t entry,
		   const assumption_map_t *assumptions)
	: _iterator(iterator),
	  _entry(entry),
	  _assumptions(assumptions),
	  _skip(true) { }

      void visit(wto_vertex_t& vertex) {
        basic_block_label_t node = vertex.node();

	/** decide whether skip vertex or not **/
	if (_skip && (node == _entry)) {
	  _skip = false;
	}
	if (_skip) {
	  CRAB_VERBOSE_IF(2,
		crab::outs() << "** Skipped analysis of  "
			     << crab::cfg_impl::get_label_str(node) << "\n");
	  return;
	}

        AbstractValue pre;
        if (node == _entry) {
          pre = this->_iterator->get_pre(node);
	  if (_assumptions) { // no necessary but it might avoid copies
	    pre = strengthen(node, pre);
	    this->_iterator->set_pre(node, pre);
	  }
        } else {
          auto prev_nodes = this->_iterator->_cfg.prev_nodes(node);
	  crab::CrabStats::resume("Fixpo.join_predecessors");
          pre = AbstractValue::bottom();
          for (basic_block_label_t prev : prev_nodes) {
            pre |= this->_iterator->get_post(prev);
          }
	  crab::CrabStats::stop("Fixpo.join_predecessors");
	  if (_assumptions) { //no necessary but it might avoid copies
	    pre = strengthen(node, pre);
	  }
          this->_iterator->set_pre(node, pre);
        }

        CRAB_VERBOSE_IF(4, crab::outs() << "PRE Invariants:\n" << pre << "\n");
        crab::CrabStats::resume ("Fixpo.analyze_block");
	AbstractValue post(pre);
        CRAB_VERBOSE_IF(1, crab::get_msg_stream() << "Analyzing node "
			                 << crab::cfg_impl::get_label_str(node);
			 auto &n = this->_iterator->_cfg.get_node(node);
			 crab::outs() << " size=" << n.size() << "\n";);
        this->_iterator->analyze(node, post);
        crab::CrabStats::stop ("Fixpo.analyze_block");
        CRAB_VERBOSE_IF(3, crab::outs() << "POST Invariants:\n" << post << "\n");
        this->_iterator->set_post(node, post);
      }

      void visit(wto_cycle_t& cycle) {
        basic_block_label_t head = cycle.head();

	/** decide whether skip cycle or not **/
	bool entry_in_this_cycle = false;
	if (_skip) {
	  // We only skip the analysis of cycle is _entry is not a
	  // component of it, included nested components.
	  member_component_visitor vis(_entry);
	  cycle.accept(&vis);
	  entry_in_this_cycle = vis.is_member();
	  _skip = !entry_in_this_cycle;
	  if (_skip) {
	    CRAB_VERBOSE_IF(2,
		 crab::outs() << "** Skipped analysis of WTO cycle rooted at  "
			      << crab::cfg_impl::get_label_str(head) << "\n");
	    return;
	  }
	}

        CRAB_VERBOSE_IF(1,
			 crab::get_msg_stream() << "** Analyzing loop with head "
			              << crab::cfg_impl::get_label_str(head);
			 auto &n = this->_iterator->_cfg.get_node(head);
			 crab::outs() << " size=" << n.size() << "\n";);

        auto prev_nodes = this->_iterator->_cfg.prev_nodes(head);
        AbstractValue pre = AbstractValue::bottom();
	wto_nesting_t cycle_nesting = this->_iterator->_wto.nesting(head);

	if (entry_in_this_cycle) {
	  CRAB_VERBOSE_IF(2,
		    crab::outs() << "Skipped predecessors of "
		  	         << crab::cfg_impl::get_label_str(head) << "\n");
	  pre = _iterator->get_pre(_entry);
	} else {
	  crab::CrabStats::count("Fixpo.join_predecessors");
	  crab::ScopedCrabStats __st__("Fixpo.join_predecessors");
	  for (basic_block_label_t prev : prev_nodes) {
	    if (!(this->_iterator->_wto.nesting(prev) > cycle_nesting)) {
	      pre |= this->_iterator->get_post(prev);
	    }
	  }
	}
	if (_assumptions) { //no necessary but it might avoid copies
	  pre = strengthen(head, pre);
	}

        for(unsigned int iteration = 1; ; ++iteration) {
	  // keep track of how many times the cycle is visited by the fixpoint
	  cycle.increment_fixpo_visits();

          // Increasing iteration sequence with widening
          this->_iterator->set_pre(head, pre);
	  CRAB_VERBOSE_IF(4, crab::outs() << "PRE Invariants:\n" << pre << "\n");
	  crab::CrabStats::resume("Fixpo.analyze_block");
          AbstractValue post(pre);
          CRAB_VERBOSE_IF(1, crab::get_msg_stream() << "Analyzing node "
			                  << crab::cfg_impl::get_label_str(head);
			  auto &n = this->_iterator->_cfg.get_node(head);
			  crab::outs() << " size=" << n.size() << "\n";);
          this->_iterator->analyze(head, post);
	  crab::CrabStats::stop("Fixpo.analyze_block");
	  CRAB_VERBOSE_IF(3, crab::outs() << "POST Invariants:\n" << post << "\n");

          this->_iterator->set_post(head, post);
          for (typename wto_cycle_t::iterator it = cycle.begin();
	       it != cycle.end(); ++it) {
            it->accept(this);
          }
	  crab::CrabStats::resume("Fixpo.join_predecessors");
          AbstractValue new_pre = AbstractValue::bottom();
          for (basic_block_label_t prev : prev_nodes) {
	    new_pre |= this->_iterator->get_post(prev);
          }
	  crab::CrabStats::stop("Fixpo.join_predecessors");
	  crab::CrabStats::resume("Fixpo.check_fixpoint");
	  bool fixpoint_reached = new_pre <= pre;
	  crab::CrabStats::stop("Fixpo.check_fixpoint");
          if (fixpoint_reached) {
            // Post-fixpoint reached
            CRAB_VERBOSE_IF(1, crab::get_msg_stream() << "post-fixpoint reached\n");
            this->_iterator->set_pre(head, new_pre);
            pre = new_pre;
            break;
          } else {
            pre = this->_iterator->extrapolate(head, iteration, pre, new_pre);
          }
        }

	if (this->_iterator->_descending_iterations == 0) {
	  // no narrowing
	  return;
	}

	CRAB_VERBOSE_IF(1, crab::get_msg_stream() << "Started narrowing phase\n";);

        for(unsigned int iteration = 1; ; ++iteration) {
          // Decreasing iteration sequence with narrowing

	  CRAB_VERBOSE_IF(4, crab::outs() << "PRE Invariants:\n" << pre << "\n");
	  crab::CrabStats::resume("Fixpo.analyze_block");
          AbstractValue post(pre);
          CRAB_VERBOSE_IF(1,crab::get_msg_stream() << "Analyzing node "
			  << crab::cfg_impl::get_label_str(head);
			  auto &n = this->_iterator->_cfg.get_node(head);
			  crab::outs() << " size=" << n.size() << "\n";);
          this->_iterator->analyze(head, post);
          this->_iterator->set_post(head, post);
	  crab::CrabStats::stop("Fixpo.analyze_block");
	  CRAB_VERBOSE_IF(3, crab::outs() << "POST Invariants:\n" << post << "\n");

          for (typename wto_cycle_t::iterator it = cycle.begin();
	       it != cycle.end(); ++it) {
            it->accept(this);
          }
	  crab::CrabStats::resume("Fixpo.join_predecessors");
          AbstractValue new_pre = AbstractValue::bottom();
          for (basic_block_label_t prev : prev_nodes) {
	    new_pre |= this->_iterator->get_post(prev);
          }
	  crab::CrabStats::stop("Fixpo.join_predecessors");
	  crab::CrabStats::resume("Fixpo.check_fixpoint");
	  bool no_more_refinement = pre <= new_pre;
	  crab::CrabStats::stop("Fixpo.check_fixpoint");
          if (no_more_refinement) {
            CRAB_VERBOSE_IF(1, crab::get_msg_stream() << "No more refinement possible.\n");
            // No more refinement possible(pre == new_pre)
            break;
          } else {
            if (iteration > this->_iterator->_descending_iterations) break;
            pre = this->_iterator->refine(head, iteration, pre, new_pre);
            this->_iterator->set_pre(head, pre);
          }
        }
        CRAB_VERBOSE_IF(1,
			 crab::get_msg_stream() << "** Finished loop with head "
			 << crab::cfg_impl::get_label_str(head) << "\n");

      }

    }; // class wto_iterator

    template<typename CFG, typename AbstractValue>
    class wto_processor: public wto_component_visitor<CFG> {

    public:
      typedef interleaved_fwd_fixpoint_iterator<CFG, AbstractValue> interleaved_iterator_t;
      typedef wto_vertex<CFG> wto_vertex_t;
      typedef wto_cycle<CFG> wto_cycle_t;
      typedef typename CFG::basic_block_label_t basic_block_label_t;

    private:
      interleaved_iterator_t *_iterator;

    public:
      wto_processor(interleaved_iterator_t *iterator): _iterator(iterator) { }

      void visit(wto_vertex_t& vertex) {
	crab::CrabStats::count("Fixpo.process_invariants");
	crab::ScopedCrabStats __st__("Fixpo.process_invariants");

        basic_block_label_t node = vertex.node();
        this->_iterator->process_pre(node, this->_iterator->get_pre(node));
        this->_iterator->process_post(node, this->_iterator->get_post(node));
      }

      void visit(wto_cycle_t& cycle) {
	crab::CrabStats::count("Fixpo.process_invariants");
	crab::ScopedCrabStats __st__("Fixpo.process_invariants");

        basic_block_label_t head = cycle.head();
        this->_iterator->process_pre(head, this->_iterator->get_pre(head));
        this->_iterator->process_post(head, this->_iterator->get_post(head));
        for (typename wto_cycle_t::iterator it = cycle.begin(); it != cycle.end(); ++it) {
          it->accept(this);
        }
      }

    }; // class wto_processor

  } // interleaved_fwd_fixpoint_iterator_impl
} // namespace ikos
