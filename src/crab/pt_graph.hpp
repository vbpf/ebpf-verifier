#pragma once

#include <vector>
#include "crab/patricia_trees.hpp"

/* Patricia-tree backed sparse weighted graph.
 * Trades some time penalty for much lower memory consumption.
 */
namespace crab {

template <class Weight>
class PtGraph : public ikos::writeable {
  public:
    typedef Weight Wt;
    typedef PtGraph<Wt> graph_t;

    typedef unsigned int vert_id;
    
    class vert_idx {
    public:
      vert_idx(vert_id _v)
        : v(_v)
      { }
      ikos::index_t index(void) const { return (ikos::index_t) v; }

      void write(crab_os& o) {
        o << v;
      }

      vert_id v;
    };

    typedef ikos::patricia_tree_set<vert_idx> pred_t;
    typedef ikos::patricia_tree<vert_idx, Wt> succ_t;

    PtGraph()
      : edge_count(0), _succs(), _preds(), is_free(), free_id()
    {

    }

    template<class Wo>
    PtGraph(const PtGraph<Wo>& o)
      : edge_count(0)
    {
      for(vert_id v : o.verts())
        for(vert_id d : o.succs(v))
          add_edge(v, o.edge_val(v, d), d);
    }

    PtGraph(const PtGraph<Wt>& o)
      : edge_count(o.edge_count), _succs(o._succs), _preds(o._preds),
        is_free(o.is_free), free_id(o.free_id)
    { }

    PtGraph(PtGraph<Wt>&& o)
      : edge_count(o.edge_count), _succs(std::move(o._succs)), _preds(std::move(o._preds)),
        is_free(std::move(o.is_free)), free_id(std::move(o.free_id))
    {
      o.edge_count = 0;
    }

    PtGraph& operator=(const PtGraph<Wt>& o)
    {
      if((&o) == this)
        return *this;  
      
      edge_count = o.edge_count;
      _succs = o._succs; 
      _preds = o._preds;
      is_free = o.is_free;
      free_id = o.free_id;

      return *this;
    }

    PtGraph& operator=(PtGraph<Wt>&& o)
    {
      edge_count = o.edge_count;
      _succs = std::move(o._succs);
      _preds = std::move(o._preds);
      is_free = std::move(o.is_free);
      free_id = std::move(o.free_id);
      
      return *this;
    }

    // void check_adjs(void)
    // {
    //   for(vert_id v : verts())
    //   {
    //     assert(succs(v).size() <= _succs.size());
    //     for(vert_id s : succs(v))
    //     {
    //       assert(s < _succs.size());
    //       assert(preds(s).mem(v));
    //     }

    //     assert(preds(v).size() <= _succs.size());
    //     for(vert_id p : preds(v))
    //     {
    //       assert(p < _succs.size());
    //       assert(succs(p).mem(v));
    //     }
    //   }
    // }

    ~PtGraph()
    { }

    // GKG: Can do this more efficiently
    template<class G> 
    static graph_t copy(G& g)
    {
      graph_t ret;
      ret.growTo(g.size());

      for(vert_id s : g.verts())
      {
        for(vert_id d : g.succs(s))
        {
          ret.add_edge(s, g.edge_val(s, d), d);
        }
      }

      return ret;
    }

    bool is_empty(void) const { return edge_count == 0; }

    vert_id new_vertex(void)
    {
      vert_id v;
      if(free_id.size() > 0)
      {
        v = free_id.back();
        assert(v < _succs.size());
        free_id.pop_back();
        is_free[v] = false;
      } else {
        v = is_free.size();
        _succs.push_back(succ_t());
        _preds.push_back(pred_t());
        is_free.push_back(false);
      }

      return v;
    }

    void forget(vert_id v)
    {
      assert(v < _succs.size());
      if(is_free[v])
        return;

      free_id.push_back(v); 
      is_free[v] = true;
      
      // Remove (s -> v) from preds.
      edge_count -= succs(v).size();
      for(vert_id d : succs(v))
        preds(d).remove(v);
      _succs[v].clear();

      // Remove (v -> p) from succs
      edge_count -= preds(v).size();
      for(vert_id p : preds(v))
        succs(p).remove(v);
      _preds[v].clear();
    }

    // Check whether an edge is live
    bool elem(vert_id x, vert_id y) {
      return succs(x).mem(y);
    }

    class mut_val_ref_t {

     public:

      mut_val_ref_t(): g(nullptr) { }

      mut_val_ref_t(graph_t& _g, vert_id _s, vert_id _d): 
          g(&_g), s(_s), d(_d), w(g->succs(s).value(d)) { }

      operator Wt () const { 
        assert (g);
        return w; 
      }

      Wt get() const { assert(g); return w;}

      void operator=(const mut_val_ref_t& o) {
        if (this != &o) {
          g = o.g;
          s = o.s;
          d = o.d;
          w = o.w;
        }
      }

      void operator=(Wt _w) {
        assert (g);
        g->set_edge(s, _w, d);
        w = _w;
      }

     private:
      graph_t* g;
      vert_id s;
      vert_id d;
      Wt w;
    };

    typedef mut_val_ref_t mut_val_ref_t;

    bool lookup(vert_id x, vert_id y, mut_val_ref_t* w) {
      if(!succs(x).mem(y))
        return false;
      (*w) = mut_val_ref_t (*this, x, y);
      return true;
    }

    // GKG: no longer a ref
    Wt edge_val(vert_id x, vert_id y) {
      return succs(x).value(y);
    }

    // Precondition: elem(x, y) is true.
    Wt operator()(vert_id x, vert_id y) {
      return succs(x).value(y);
    }

    void clear_edges(void) {
      edge_count = 0;
      for(vert_id v : verts())
      {
        _succs[v].clear();
        _preds[v].clear();
      }
    }

    void clear(void)
    {
      edge_count = 0;
      is_free.clear();
      free_id.clear();
      _succs.clear();
      _preds.clear();
    }

    // Number of allocated vertices
    int size(void) const {
      return is_free.size();
    }

    // Number of edges
    size_t num_edges(void) const { return edge_count;}  
  
    // Assumption: (x, y) not in mtx

    void add_edge(vert_id x, Wt wt, vert_id y)
    {
      succs(x).add(y, wt);
      preds(y).add(x);
      edge_count++;
    }

    void set_edge(vert_id s, Wt w, vert_id d)
    {
      // assert(s < size() && d < size());
      if(!elem(s, d))
        add_edge(s, w, d);
      else
        _succs[s].insert(vert_idx(d), w);
    }

    template<class Op>
    void update_edge(vert_id s, Wt w, vert_id d, Op& op)
    {
      if(elem(s, d))
      {
        // _succs[s].insert(vert_idx(d), w, op);
        _succs[s].insert(vert_idx(d), op.apply(edge_val(s, d), w));
        return;
      }

      if(!op.default_is_absorbing())
        add_edge(s, w, d);
    }

    class vert_iterator {
    public:
      vert_iterator(vert_id _v, const std::vector<bool>& _is_free)
        : v(_v), is_free(_is_free)
      { }
      vert_id operator*(void) const { return v; }
      vert_iterator& operator++(void) { ++v; return *this; }
      // vert_iterator& operator--(void) { --v; return *this; }
      bool operator!=(const vert_iterator& o) {
        while(v < o.v && is_free[v])
          ++v;
        return v < o.v;
      }
    protected:
      vert_id v;
      const std::vector<bool>& is_free;
    };

    class vert_range {
    public:
      vert_range(const std::vector<bool>& _is_free)
        : is_free(_is_free)
      { }
      vert_iterator begin(void) const { return vert_iterator(0, is_free); }
      vert_iterator end(void) const { return vert_iterator(is_free.size(), is_free); }
    protected:
      const std::vector<bool>& is_free;
    };

    // FIXME: Verts currently iterates over free vertices,
    // as well as existing ones
    vert_range verts(void) const { return vert_range(is_free); }

    class pred_iterator {
    public:
      typedef typename pred_t::iterator ItP;
      typedef pred_iterator iter_t;

      pred_iterator(const ItP& _it)
        : it(_it)
      { }
      pred_iterator(void)
        : it()
      { }
      bool operator!=(const iter_t& o) {
        return it != o.it;
      }
      iter_t& operator++(void) { ++it; return *this; }
      vert_id operator*(void) const { return (*it).v; }
    protected:
      ItP it;
    };

    class succ_iterator {
    public:
      typedef typename succ_t::iterator ItS;
      typedef succ_iterator iter_t;
      succ_iterator(const ItS& _it)
        : it(_it)
      { }
      succ_iterator(void)
        : it()
      { }
      // XXX: to make sure that we always return the same address
      // for the "empty" iterator, otherwise we can trigger
      // undefined behavior.
      static iter_t empty_iterator () { 
	static std::unique_ptr<iter_t> it = nullptr;
	if (!it)
	  it = std::unique_ptr<iter_t>(new iter_t ());
	return *it;
      }
      bool operator!=(const iter_t& o) {
        return it != o.it;
      }
      iter_t& operator++(void) { ++it; return *this; }
      vert_id operator*(void) const { return (*it).first.v; }
    protected:
      ItS it;      
    };

    class pred_range {
    public:
      typedef pred_iterator iterator;

      pred_range(pred_t& _p)
        : p(_p)
      { }
      iterator begin(void) const { return iterator(p.begin()); }
      iterator end(void) const { return iterator(p.end()); }
      size_t size(void) const { return p.size(); }

      bool mem(unsigned int v) const { return p[v]; }
      void add(unsigned int v) { p += v; }
      void remove(unsigned int v) { p -= v; }
      void clear() { p.clear(); }

    protected:
      pred_t& p;
    };

    class succ_range {
    public:
      typedef succ_iterator iterator;

      succ_range(succ_t& _p)
        : p(_p)
      { }
      iterator begin(void) const { return iterator(p.begin()); }
      iterator end(void) const { return iterator(p.end()); }
      size_t size(void) const { return p.size(); }

      bool mem(unsigned int v) const { 
        if (p.lookup(v)) 
          return true;
        else
          return false;        
      }
      void add(unsigned int v, const Wt& w) { p.insert(v, w); }
      Wt value(unsigned int v) const { return *(p.lookup (v)); }
      void remove(unsigned int v) { p.remove(v); }
      void clear() { p.clear(); }

    protected:
      succ_t& p;
    };

    class edge_ref_t {
    public:
      edge_ref_t(vert_id _v, Wt _w)
        : vert(_v), val(_w)
      { }
      vert_id vert;
      Wt val; // no longer a ref
    };

    class const_edge_ref_t {
     public:
      const_edge_ref_t(vert_id _v, const Wt& _w)
        : vert(_v), val(_w)
      { }
      vert_id vert;
      const Wt& val;
    };

    class fwd_edge_iterator {
    public:
      typedef edge_ref_t edge_ref;
      fwd_edge_iterator(void)
        : g(nullptr)
      { }
      fwd_edge_iterator(graph_t& _g, vert_id _s, succ_iterator _it)
        : g(&_g), s(_s), it(_it)
      { }
      // XXX: to make sure that we always return the same address
      // for the "empty" iterator, otherwise we can trigger
      // undefined behavior.
      static fwd_edge_iterator empty_iterator () { 
	static std::unique_ptr<fwd_edge_iterator> it = nullptr;
	if (!it)
	  it = std::unique_ptr<fwd_edge_iterator>(new fwd_edge_iterator ());
	return *it;
      }

      edge_ref operator*(void) const { return edge_ref((*it), g->edge_val(s, (*it))); }
      fwd_edge_iterator& operator++(void) { ++it; return *this; }
      bool operator!=(const fwd_edge_iterator& o) { return it != o.it; }

      graph_t* g;
      vert_id s;
      succ_iterator it;
    };

    class fwd_edge_range {
    public:
      typedef fwd_edge_iterator iterator;
      fwd_edge_range(graph_t& _g, vert_id _s)
        : g(_g), s(_s)
      { }

      fwd_edge_iterator begin(void) const { return fwd_edge_iterator(g, s, g.succs(s).begin()); }
      fwd_edge_iterator end(void) const { return fwd_edge_iterator(g, s, g.succs(s).end()); }
      graph_t& g;
      vert_id s;
    };

    class rev_edge_iterator {
    public:
      typedef edge_ref_t edge_ref;
      rev_edge_iterator(void)
        : g(nullptr)
      { }
      rev_edge_iterator(graph_t& _g, vert_id _d, pred_iterator _it)
        : g(&_g), d(_d), it(_it)
      { }

      edge_ref operator*(void) const { return edge_ref((*it), g->edge_val((*it), d)); }
      rev_edge_iterator& operator++(void) { ++it; return *this; }
      bool operator!=(const rev_edge_iterator& o) { return it != o.it; }

      graph_t* g;
      vert_id d;
      pred_iterator it;
    };

    class rev_edge_range {
    public:
      typedef rev_edge_iterator iterator;
      rev_edge_range(graph_t& _g, vert_id _d)
        : g(_g), d(_d)
      { }

      rev_edge_iterator begin(void) const { return rev_edge_iterator(g, d, g.preds(d).begin()); }
      rev_edge_iterator end(void) const { return rev_edge_iterator(g, d, g.preds(d).end()); }
      graph_t& g;
      vert_id d;
    };


    typedef fwd_edge_range e_succ_range;
    typedef rev_edge_range e_pred_range;


    succ_range succs(vert_id v)
    {
      return succ_range(_succs[v]);
    }

    e_succ_range e_succs(vert_id v) 
    {
      return fwd_edge_range (*this, v);
    }

    pred_range preds(vert_id v)
    {
      return pred_range(_preds[v]);
    }

    e_pred_range e_preds(vert_id v) 
    {
      return rev_edge_range (*this, v);
    }

    // growTo shouldn't be used after forget
    void growTo(unsigned int new_sz)
    {
      size_t sz = is_free.size();
      for(; sz < new_sz; sz++)
      {
        is_free.push_back(false);
        _preds.push_back(pred_t());
        _succs.push_back(succ_t());
      }
      assert(free_id.size() == 0);
    }

    void write(crab_os& o) {
      o << "[|";
      bool first = true;
      for(vert_id v = 0; v < _succs.size(); v++)
      {
        auto it = succs(v).begin();
        auto end = succs(v).end();

        if(it != end)
        {
          if(first)
            first = false;
          else
            o << ", ";

          o << "[v" << v << " -> ";
          o << "(" << edge_val(v, *it) << ":" << *it << ")";
          for(++it; it != end; ++it)
          {
            o << ", (" << edge_val(v, *it) << ":" << *it << ")";
          }
          o << "]";
        }
      }
      o << "|]";
    }

  protected:

    unsigned int edge_count;

    std::vector<succ_t> _succs;
    std::vector<pred_t> _preds;

    std::vector<bool> is_free;
    std::vector<int> free_id;
};

}
