#pragma once

#include "crab/Vec.h"
// Adaptive sparse-set based weighted graph implementation

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"

namespace crab {
// An adaptive sparse-map.
// Starts off as an unsorted vector, switching to a
// sparse-set when |S| >= sparse_threshold
// WARNING: Assumes Val is a basic type (so doesn't need a ctor/dtor call)
template <class Val>
class AdaptSMap {
    enum { sparse_threshold = 8 };

  public:
    typedef uint16_t key_t;
    typedef Val val_t;
    class elt_t {
      public:
        elt_t(key_t _k, const val_t &_v) : key(_k), val(_v) {}

        elt_t(const elt_t &o) : key(o.key), val(o.val) {}

        key_t key;
        val_t val;
    };

    AdaptSMap(void)
        : sz(0), dense_maxsz(sparse_threshold), sparse_ub(10), dense((elt_t *)malloc(sizeof(elt_t) * sparse_threshold)),
          sparse(nullptr) {}

    AdaptSMap(AdaptSMap &&o)
        : sz(o.sz), dense_maxsz(o.dense_maxsz), sparse_ub(o.sparse_ub), dense(o.dense), sparse(o.sparse) {
        o.dense = nullptr;
        o.sparse = nullptr;
        o.sz = 0;
        o.dense_maxsz = 0;
        o.sparse_maxsz = 0;
    }

    AdaptSMap(const AdaptSMap &o)
        : sz(o.sz), dense_maxsz(o.dense_maxsz), sparse_ub(o.sparse_ub),
          dense((elt_t *)malloc(sizeof(elt_t) * dense_maxsz)), sparse(nullptr) {
        memcpy(static_cast<void *>(dense), o.dense, sizeof(elt_t) * sz);

        if (o.sparse) {
            sparse = (key_t *)malloc(sizeof(key_t) * sparse_ub);
            for (key_t idx = 0; idx < sz; idx++)
                sparse[dense[idx].key] = idx;
        }
    }

    AdaptSMap &operator=(const AdaptSMap &o) {
        if (this != &o) {
            if (dense_maxsz < o.dense_maxsz) {
                dense_maxsz = o.dense_maxsz;
                dense = (elt_t *)realloc(static_cast<void *>(dense), sizeof(elt_t) * dense_maxsz);
            }
            sz = o.sz;
            memcpy(static_cast<void *>(dense), o.dense, sizeof(elt_t) * sz);

            if (o.sparse) {
                if (!sparse || sparse_ub < o.sparse_ub) {
                    sparse_ub = o.sparse_ub;
                    sparse = (key_t *)realloc(static_cast<void *>(sparse), sizeof(key_t) * sparse_ub);
                }
            }

            if (sparse) {
                for (key_t idx = 0; idx < sz; idx++)
                    sparse[dense[idx].key] = idx;
            }
        }

        return *this;
    }

    AdaptSMap &operator=(AdaptSMap &&o) {
        if (dense)
            free(dense);
        if (sparse)
            free(sparse);

        dense = o.dense;
        o.dense = nullptr;
        sparse = o.sparse;
        o.sparse = nullptr;

        sz = o.sz;
        o.sz = 0;
        dense_maxsz = o.dense_maxsz;
        o.dense_maxsz = 0;
        sparse_ub = o.sparse_ub;
        o.sparse_ub = 0;
        return *this;
    }

    ~AdaptSMap(void) {
        if (dense)
            free(dense);
        if (sparse)
            free(sparse);
    }

    size_t size(void) const { return sz; }

    class key_iter_t {
      public:
        key_iter_t(void) : e(nullptr) {}
        key_iter_t(elt_t *_e) : e(_e) {}

        // XXX: to make sure that we always return the same address
        // for the "empty" iterator, otherwise we can trigger
        // undefined behavior.
        static key_iter_t empty_iterator() {
            static std::unique_ptr<key_iter_t> it = nullptr;
            if (!it)
                it = std::unique_ptr<key_iter_t>(new key_iter_t());
            return *it;
        }

        key_t operator*(void)const { return (*e).key; }
        bool operator!=(const key_iter_t &o) const { return e < o.e; }
        key_iter_t &operator++(void) {
            ++e;
            return *this;
        }

        elt_t *e;
    };
    typedef elt_t *elt_iter_t;

    class key_range_t {
      public:
        typedef key_iter_t iterator;

        key_range_t(elt_t *_e, size_t _sz) : e(_e), sz(_sz) {}
        size_t size(void) const { return sz; }

        key_iter_t begin(void) const { return key_iter_t(e); }
        key_iter_t end(void) const { return key_iter_t(e + sz); }

        elt_t *e;
        size_t sz;
    };

    class elt_range_t {
      public:
        typedef elt_iter_t iterator;

        elt_range_t(elt_t *_e, size_t _sz) : e(_e), sz(_sz) {}
        elt_range_t(const elt_range_t &o) : e(o.e), sz(o.sz) {}
        size_t size(void) const { return sz; }
        elt_iter_t begin(void) const { return elt_iter_t(e); }
        elt_iter_t end(void) const { return elt_iter_t(e + sz); }

        elt_t *e;
        size_t sz;
    };

    elt_range_t elts(void) const { return elt_range_t(dense, sz); }
    key_range_t keys(void) const { return key_range_t(dense, sz); }

    bool elem(key_t k) const {
        if (sparse) {
            // NOTE: This can (often will) read beyond the bounds of sparse.
            // This is totally okay. But valgrind will complain, and
            // compiling with AddressSanitizer will probably break.
            int idx = sparse[k];
            return (idx < sz) && dense[idx].key == k;
        } else {
            for (key_t ke : keys()) {
                if (ke == k)
                    return true;
            }
            return false;
        }
    }

    bool lookup(key_t k, val_t *v_out) {
        if (sparse) {
            // SEE ABOVE WARNING
            int idx = sparse[k];
            if (idx < sz && dense[idx].key == k) {
                (*v_out) = dense[idx].val;
                return true;
            }
            return false;
        } else {
            for (elt_t elt : elts()) {
                if (elt.key == k) {
                    (*v_out) = elt.val;
                    return true;
                }
            }
            return false;
        }
    }

    // precondition: k \in S
    void remove(key_t k) {
        --sz;
        elt_t repl = dense[sz];
        if (sparse) {
            int idx = sparse[k];

            dense[idx] = repl;
            sparse[repl.key] = idx;
        } else {
            elt_t *e = dense;
            while (e->key != k)
                ++e;
            *e = repl;
        }
    }

    // precondition: k \notin S
    void add(key_t k, const val_t &v) {
        if (dense_maxsz <= sz)
            growDense(sz + 1);

        dense[sz] = elt_t(k, v);
        if (sparse) {
            if (sparse_ub <= k)
                growSparse(k + 1);
            sparse[k] = sz;
        }
        sz++;
    }

    void growDense(size_t new_max) {
        assert(dense_maxsz < new_max);

        while (dense_maxsz < new_max)
            dense_maxsz *= 2;
        elt_t *new_dense = (elt_t *)realloc(static_cast<void *>(dense), sizeof(elt_t) * dense_maxsz);
        if (!new_dense)
            CRAB_ERROR("Allocation failure.");
        dense = new_dense;

        if (!sparse) {
            // After resizing the first time, we switch to an sset.
            key_t key_max = 0;
            for (key_t k : keys())
                key_max = std::max(key_max, k);

            sparse_ub = key_max + 1;
            sparse = (key_t *)malloc(sizeof(key_t) * sparse_ub);
            key_t idx = 0;
            for (key_t k : keys())
                sparse[k] = idx++;
        }
    }

    void growSparse(size_t new_ub) {
        while (sparse_ub < new_ub)
            sparse_ub *= 2;
        key_t *new_sparse = (key_t *)malloc(sizeof(key_t) * (sparse_ub));
        if (!new_sparse)
            CRAB_ERROR("Allocation falure.");
        free(sparse);
        sparse = new_sparse;

        key_t idx = 0;
        for (key_t k : keys())
            sparse[k] = idx++;
    }

    void clear(void) { sz = 0; }

    size_t sz;
    size_t dense_maxsz;
    size_t sparse_ub;
    elt_t *dense;
    key_t *sparse;
};

template <class Weight>
class AdaptGraph : public ikos::writeable {
    typedef AdaptSMap<size_t> smap_t;

  public:
    typedef unsigned int vert_id;
    typedef Weight Wt;

    AdaptGraph(void) : edge_count(0) {}

    AdaptGraph(AdaptGraph<Wt> &&o)
        : _preds(std::move(o._preds)), _succs(std::move(o._succs)), _ws(std::move(o._ws)), edge_count(o.edge_count),
          is_free(std::move(o.is_free)), free_id(std::move(o.free_id)), free_widx(std::move(o.free_widx)) {}

    AdaptGraph(const AdaptGraph<Wt> &o)
        : _preds(o._preds), _succs(o._succs), _ws(o._ws), edge_count(o.edge_count), is_free(o.is_free),
          free_id(o.free_id), free_widx(o.free_widx) {}

    AdaptGraph<Wt> &operator=(const AdaptGraph<Wt> &o) {
        if (this != &o) {
            _preds = o._preds;
            _succs = o._succs;
            _ws = o._ws;
            edge_count = o.edge_count;
            is_free = o.is_free;
            free_id = o.free_id;
            free_widx = o.free_widx;
        }
        return *this;
    }

    AdaptGraph<Wt> &operator=(AdaptGraph<Wt> &&o) {
        _preds = std::move(o._preds);
        _succs = std::move(o._succs);
        _ws = std::move(o._ws);
        edge_count = o.edge_count;
        is_free = std::move(o.is_free);
        free_id = std::move(o.free_id);
        free_widx = std::move(o.free_widx);

        return *this;
    }

    template <class G>
    static AdaptGraph<Wt> copy(const G &o) {
        AdaptGraph<Wt> g;
        g.growTo(o.size());

        for (vert_id s : o.verts()) {
            for (auto e : const_cast<G &>(o).e_succs(s)) {
                g.add_edge(s, e.val, e.vert);
            }
        }
        return g;
    }

    class vert_iterator {
      public:
        vert_iterator(vert_id _v, const std::vector<bool> &_is_free) : v(_v), is_free(_is_free) {}
        vert_id operator*(void)const { return v; }
        bool operator!=(const vert_iterator &o) {
            while (v < o.v && is_free[v])
                ++v;
            return v < o.v;
        }
        vert_iterator &operator++(void) {
            ++v;
            return *this;
        }

        vert_id v;
        const std::vector<bool> &is_free;
    };
    class vert_range {
      public:
        vert_range(const std::vector<bool> &_is_free) : is_free(_is_free) {}

        vert_iterator begin(void) const { return vert_iterator(0, is_free); }
        vert_iterator end(void) const { return vert_iterator(is_free.size(), is_free); }

        size_t size(void) const { return is_free.size(); }
        const std::vector<bool> &is_free;
    };
    vert_range verts(void) const { return vert_range(is_free); }

    class edge_ref_t {
      public:
        edge_ref_t(vert_id _vert, Wt &_val) : vert(_vert), val(_val) {}
        vert_id vert;
        Wt &val;
    };

    class edge_iter {
      public:
        typedef edge_ref_t edge_ref;
        edge_iter(const smap_t::elt_iter_t &_it, vec<Wt> &_ws) : it(_it), ws(&_ws) {}
        edge_iter(const edge_iter &o) : it(o.it), ws(o.ws) {}
        edge_iter(void) : ws(nullptr) {}

        // XXX: to make sure that we always return the same address
        // for the "empty" iterator, otherwise we can trigger
        // undefined behavior.
        static edge_iter empty_iterator() {
            static std::unique_ptr<edge_iter> it = nullptr;
            if (!it)
                it = std::unique_ptr<edge_iter>(new edge_iter());
            return *it;
        }

        edge_ref operator*(void)const { return edge_ref((*it).key, (*ws)[(*it).val]); }
        edge_iter operator++(void) {
            ++it;
            return *this;
        }
        bool operator!=(const edge_iter &o) { return it != o.it; }

        smap_t::elt_iter_t it;
        vec<Wt> *ws;
    };

    typedef typename smap_t::key_range_t adj_range_t;
    typedef typename adj_range_t::iterator adj_iterator_t;

    class edge_range_t {
      public:
        typedef typename smap_t::elt_range_t elt_range_t;
        typedef edge_iter iterator;
        edge_range_t(const edge_range_t &o) : r(o.r), ws(o.ws) {}
        edge_range_t(const elt_range_t &_r, vec<Wt> &_ws) : r(_r), ws(_ws) {}

        edge_iter begin(void) const { return edge_iter(r.begin(), ws); }
        edge_iter end(void) const { return edge_iter(r.end(), ws); }
        size_t size(void) const { return r.size(); }

        elt_range_t r;
        vec<Wt> &ws;
    };

    typedef edge_iter fwd_edge_iter;
    typedef edge_iter rev_edge_iter;

    typedef adj_range_t pred_range;
    typedef adj_range_t succ_range;

    adj_range_t succs(vert_id v) { return _succs[v].keys(); }
    adj_range_t preds(vert_id v) { return _preds[v].keys(); }

    typedef edge_range_t fwd_edge_range;
    typedef edge_range_t rev_edge_range;

    edge_range_t e_succs(vert_id v) { return edge_range_t(_succs[v].elts(), _ws); }
    edge_range_t e_preds(vert_id v) { return edge_range_t(_preds[v].elts(), _ws); }

    typedef edge_range_t e_pred_range;
    typedef edge_range_t e_succ_range;

    // Management
    bool is_empty(void) const { return edge_count == 0; }
    size_t size(void) const { return _succs.size(); }
    size_t num_edges(void) const { return edge_count; }
    vert_id new_vertex(void) {
        vert_id v;
        if (free_id.size() > 0) {
            v = free_id.last();
            assert(v < _succs.size());
            free_id.pop();
            is_free[v] = false;
        } else {
            v = _succs.size();
            is_free.push_back(false);
            _succs.push();
            _preds.push();
        }

        return v;
    }

    void growTo(vert_id v) {
        while (size() < v)
            new_vertex();
    }

    void forget(vert_id v) {
        if (is_free[v])
            return;

        for (smap_t::elt_t &e : _succs[v].elts()) {
            free_widx.push(e.val);
            _preds[e.key].remove(v);
        }
        edge_count -= _succs[v].size();
        _succs[v].clear();

        for (smap_t::key_t k : _preds[v].keys())
            _succs[k].remove(v);
        edge_count -= _preds[v].size();
        _preds[v].clear();

        is_free[v] = true;
        free_id.push(v);
    }

    void clear_edges(void) {
        _ws.clear();
        for (vert_id v : verts()) {
            _succs[v].clear();
            _preds[v].clear();
        }
        edge_count = 0;
    }
    void clear(void) {
        _ws.clear();
        _succs.clear();
        _preds.clear();
        is_free.clear();
        free_id.clear();
        free_widx.clear();

        edge_count = 0;
    }

    bool elem(vert_id s, vert_id d) { return _succs[s].elem(d); }

    Wt &edge_val(vert_id s, vert_id d) {
        size_t idx;
        _succs[s].lookup(d, &idx);
        return _ws[idx];
    }

    class mut_val_ref_t {
      public:
        mut_val_ref_t() : w(nullptr) {}
        operator Wt() const {
            assert(w);
            return *w;
        }
        Wt get() const {
            assert(w);
            return *w;
        }
        void operator=(Wt *_w) { w = _w; }
        void operator=(Wt _w) {
            assert(w);
            *w = _w;
        }

      private:
        Wt *w;
    };

    typedef mut_val_ref_t mut_val_ref_t;

    bool lookup(vert_id s, vert_id d, mut_val_ref_t *w) {
        size_t idx;
        if (_succs[s].lookup(d, &idx)) {
            (*w) = &(_ws[idx]);
            return true;
        }
        return false;
    }

    void add_edge(vert_id s, Wt w, vert_id d) {
        size_t idx;
        if (free_widx.size() > 0) {
            idx = free_widx.last();
            free_widx.pop();
            _ws[idx] = w;
        } else {
            idx = _ws.size();
            _ws.push(w);
        }

        _succs[s].add(d, idx);
        _preds[d].add(s, idx);
        edge_count++;
    }

    template <class Op>
    void update_edge(vert_id s, Wt w, vert_id d, Op &op) {
        size_t idx;
        if (_succs[s].lookup(d, &idx)) {
            _ws[idx] = op.apply(_ws[idx], w);
        } else {
            if (!op.default_is_absorbing())
                add_edge(s, w, d);
        }
    }

    void set_edge(vert_id s, Wt w, vert_id d) {
        size_t idx;
        if (_succs[s].lookup(d, &idx)) {
            _ws[idx] = w;
        } else {
            add_edge(s, w, d);
        }
    }

    void write(crab_os &o) {
        o << "[|";
        bool first = true;
        for (vert_id v : verts()) {
            auto it = e_succs(v).begin();
            auto end = e_succs(v).end();

            if (it != end) {
                if (first)
                    first = false;
                else
                    o << ", ";

                o << "[v" << v << " -> ";
                o << "(" << (*it).val << ":" << (*it).vert << ")";
                for (++it; it != end; ++it) {
                    o << ", (" << (*it).val << ":" << (*it).vert << ")";
                }
                o << "]";
            }
        }
        o << "|]";
    }

    // Ick. This'll have another indirection on every operation.
    // We'll see what the performance costs are like.
    vec<smap_t> _preds;
    vec<smap_t> _succs;
    vec<Wt> _ws;

    int edge_count;

    std::vector<bool> is_free;
    vec<vert_id> free_id;
    vec<size_t> free_widx;
};
} // namespace crab
#pragma GCC diagnostic pop
