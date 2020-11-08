#pragma once

#include <memory>

#include "crab_utils/safeint.hpp"
#include "debug.hpp"
// Adaptive sparse-set based weighted graph implementation

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"

namespace crab {
// An adaptive sparse-map.
// Starts off as an unsorted vector, switching to a
// sparse-set when |S| >= sparse_threshold
// WARNING: Assumes Val is a basic type (so doesn't need a ctor/dtor call)

class AdaptSMap final {
    using Val = size_t;
    static constexpr int sparse_threshold = 1;

  public:
    using key_t = uint16_t;
    using val_t = Val;
    struct elt_t {
        key_t key;
        val_t val;
    };

    AdaptSMap()
        : sz(0), dense_maxsz(sparse_threshold), sparse_ub(10), dense((elt_t*)malloc(sizeof(elt_t) * sparse_threshold)),
          sparse(nullptr) {}

    AdaptSMap(AdaptSMap&& o) noexcept
        : sz(o.sz), dense_maxsz(o.dense_maxsz), sparse_ub(o.sparse_ub), dense(o.dense), sparse(o.sparse) {
        o.dense = nullptr;
        o.sparse = nullptr;
        o.sz = 0;
        o.dense_maxsz = 0;
    }

    AdaptSMap(const AdaptSMap& o)
        : sz(o.sz), dense_maxsz(o.dense_maxsz), sparse_ub(o.sparse_ub),
          dense((elt_t*)malloc(sizeof(elt_t) * dense_maxsz)), sparse(nullptr) {
        memcpy(static_cast<void*>(dense), o.dense, sizeof(elt_t) * sz);

        if (o.sparse) {
            sparse = (key_t*)malloc(sizeof(key_t) * sparse_ub);
            for (key_t idx = 0; idx < sz; idx++)
                sparse[dense[idx].key] = idx;
        }
    }

    AdaptSMap& operator=(const AdaptSMap& o) {
        if (this != &o) {
            if (dense_maxsz < o.dense_maxsz) {
                dense_maxsz = o.dense_maxsz;
                dense = (elt_t*)realloc(static_cast<void*>(dense), sizeof(elt_t) * dense_maxsz);
            }
            sz = o.sz;
            memcpy(static_cast<void*>(dense), o.dense, sizeof(elt_t) * sz);

            if (o.sparse) {
                if (!sparse || sparse_ub < o.sparse_ub) {
                    sparse_ub = o.sparse_ub;
                    sparse = (key_t*)realloc(static_cast<void*>(sparse), sizeof(key_t) * sparse_ub);
                }
            }

            if (sparse) {
                for (key_t idx = 0; idx < sz; idx++)
                    sparse[dense[idx].key] = idx;
            }
        }

        return *this;
    }

    AdaptSMap& operator=(AdaptSMap&& o) noexcept {
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

    ~AdaptSMap() {
        if (dense)
            free(dense);
        if (sparse)
            free(sparse);
    }

    [[nodiscard]] size_t size() const { return sz; }

    class key_iter_t {
      public:
        key_iter_t() : e(nullptr) {}
        explicit key_iter_t(const elt_t* _e) : e(_e) {}

        // XXX: to make sure that we always return the same address
        // for the "empty" iterator, otherwise we can trigger
        // undefined behavior.
        static key_iter_t empty_iterator() {
            static std::unique_ptr<key_iter_t> it = nullptr;
            if (!it)
                it = std::make_unique<key_iter_t>();
            return *it;
        }

        key_t operator*() const { return (*e).key; }
        bool operator!=(const key_iter_t& o) const { return e < o.e; }
        key_iter_t& operator++() {
            ++e;
            return *this;
        }

        const elt_t* e;
    };
    using elt_iter_t = const elt_t*;

    class key_range_t {
      public:
        using iterator = key_iter_t;

        key_range_t(const elt_t* _e, size_t _sz) : e(_e), sz(_sz) {}
        [[nodiscard]] size_t size() const { return sz; }

        [[nodiscard]] key_iter_t begin() const { return key_iter_t(e); }
        [[nodiscard]] key_iter_t end() const { return key_iter_t(e + sz); }

        const elt_t* e;
        size_t sz;
    };

    class elt_range_t {
      public:
        using iterator = elt_iter_t;

        elt_range_t(const elt_t* _e, size_t _sz) : e(_e), sz(_sz) {}
        elt_range_t(const elt_range_t& o) = default;
        [[nodiscard]] size_t size() const { return sz; }
        [[nodiscard]] elt_iter_t begin() const { return e; }
        [[nodiscard]] elt_iter_t end() const { return e + sz; }

        const elt_t* e;
        size_t sz;
    };

    [[nodiscard]] elt_range_t elts() const { return elt_range_t(dense, sz); }
    [[nodiscard]] key_range_t keys() const { return key_range_t(dense, sz); }

    [[nodiscard]] bool elem(key_t k) const {
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

    bool lookup(key_t k, val_t* v_out) const {
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
            elt_t* e = dense;
            while (e->key != k)
                ++e;
            *e = repl;
        }
    }

    // precondition: k \notin S
    void add(key_t k, const val_t& v) {
        if (dense_maxsz <= sz)
            growDense(sz + 1);

        dense[sz] = elt_t{k, v};
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
        auto* new_dense = (elt_t*)realloc(static_cast<void*>(dense), sizeof(elt_t) * dense_maxsz);
        if (!new_dense)
            CRAB_ERROR("Allocation failure.");
        dense = new_dense;

        if (!sparse) {
            // After resizing the first time, we switch to an sset.
            key_t key_max = 0;
            for (key_t k : keys())
                key_max = std::max(key_max, k);

            sparse_ub = key_max + 1;
            sparse = (key_t*)malloc(sizeof(key_t) * sparse_ub);
            key_t idx = 0;
            for (key_t k : keys())
                sparse[k] = idx++;
        }
    }

    void growSparse(size_t new_ub) {
        while (sparse_ub < new_ub)
            sparse_ub *= 2;
        auto* new_sparse = (key_t*)malloc(sizeof(key_t) * (sparse_ub));
        if (!new_sparse)
            CRAB_ERROR("Allocation falure.");
        free(sparse);
        sparse = new_sparse;

        key_t idx = 0;
        for (key_t k : keys())
            sparse[k] = idx++;
    }

    void clear() { sz = 0; }

    size_t sz;
    size_t dense_maxsz;
    size_t sparse_ub;
    elt_t* dense;
    key_t* sparse;
};

class AdaptGraph final {
    using Weight = safe_i64;  // same as SafeInt64DefaultParams::Wt; previously template
    using smap_t = AdaptSMap;

  public:
    using vert_id = unsigned int;
    using Wt = Weight;

    AdaptGraph() : edge_count(0) {}

    AdaptGraph(AdaptGraph&& o) noexcept
        : _preds(std::move(o._preds)), _succs(std::move(o._succs)), _ws(std::move(o._ws)), edge_count(o.edge_count),
          is_free(std::move(o.is_free)), free_id(std::move(o.free_id)), free_widx(std::move(o.free_widx)) {}

    AdaptGraph(const AdaptGraph& o) = default;

    AdaptGraph& operator=(const AdaptGraph& o) = default;

    AdaptGraph& operator=(AdaptGraph&& o) noexcept = default;

    template <class G>
    static AdaptGraph copy(const G& o) {
        AdaptGraph g;
        g.growTo(o.size());

        for (vert_id s : o.verts()) {
            for (auto e : const_cast<G&>(o).e_succs(s)) {
                g.add_edge(s, e.val, e.vert);
            }
        }
        return g;
    }

    struct vert_iterator {
        vert_id v;
        const std::vector<int>& is_free;

        vert_id operator*() const { return v; }

        bool operator!=(const vert_iterator& o) {
            while (v < o.v && is_free[v])
                ++v;
            return v < o.v;
        }

        vert_iterator& operator++() {
            ++v;
            return *this;
        }
    };
    struct vert_range {
        const std::vector<int>& is_free;

        explicit vert_range(const std::vector<int>& _is_free) : is_free(_is_free) {}

        [[nodiscard]] vert_iterator begin() const { return vert_iterator{0, is_free}; }
        [[nodiscard]] vert_iterator end() const { return vert_iterator{static_cast<vert_id>(is_free.size()), is_free}; }

        [[nodiscard]] size_t size() const { return is_free.size(); }
    };
    [[nodiscard]] vert_range verts() const { return vert_range{is_free}; }

    struct edge_iter {
        struct edge_ref {
            vert_id vert;
            Wt& val;
        };

        smap_t::elt_iter_t it{};
        std::vector<Wt>* ws{};

        edge_iter(const smap_t::elt_iter_t& _it, std::vector<Wt>& _ws) : it(_it), ws(&_ws) {}
        edge_iter(const edge_iter& o) = default;
        edge_iter() = default;

        // XXX: to make sure that we always return the same address
        // for the "empty" iterator, otherwise we can trigger
        // undefined behavior.
        static edge_iter empty_iterator() {
            static std::unique_ptr<edge_iter> it = nullptr;
            if (!it)
                it = std::make_unique<edge_iter>();
            return *it;
        }

        edge_ref operator*() const { return edge_ref{(*it).key, (*ws)[(*it).val]}; }
        edge_iter operator++() {
            ++it;
            return *this;
        }
        bool operator!=(const edge_iter& o) const { return it != o.it; }
    };

    using adj_range_t = typename smap_t::key_range_t;

    struct edge_range_t {
        using elt_range_t = typename smap_t::elt_range_t;
        using iterator = edge_iter;

        elt_range_t r;
        std::vector<Wt>& ws;

        [[nodiscard]] edge_iter begin() const { return edge_iter(r.begin(), ws); }
        [[nodiscard]] edge_iter end() const { return edge_iter(r.end(), ws); }
        [[nodiscard]] size_t size() const { return r.size(); }
    };

    using fwd_edge_iter = edge_iter;
    using rev_edge_iter = edge_iter;

    using pred_range = adj_range_t;
    using succ_range = adj_range_t;

    adj_range_t succs(vert_id v) { return _succs[v].keys(); }
    adj_range_t preds(vert_id v) { return _preds[v].keys(); }

    using fwd_edge_range = edge_range_t;
    using rev_edge_range = edge_range_t;

    edge_range_t e_succs(vert_id v) { return {_succs[v].elts(), _ws}; }
    edge_range_t e_preds(vert_id v) { return {_preds[v].elts(), _ws}; }

    using e_pred_range = edge_range_t;
    using e_succ_range = edge_range_t;

    // Management
    [[nodiscard]] bool is_empty() const { return edge_count == 0; }
    [[nodiscard]] size_t size() const { return _succs.size(); }
    [[nodiscard]] size_t num_edges() const { return edge_count; }
    vert_id new_vertex() {
        vert_id v;
        if (!free_id.empty()) {
            v = free_id.back();
            assert(v < _succs.size());
            free_id.pop_back();
            is_free[v] = false;
        } else {
            v = _succs.size();
            is_free.push_back(false);
            _succs.emplace_back();
            _preds.emplace_back();
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

        for (const smap_t::elt_t& e : _succs[v].elts()) {
            free_widx.push_back(e.val);
            _preds[e.key].remove(v);
        }
        edge_count -= _succs[v].size();
        _succs[v].clear();

        for (smap_t::key_t k : _preds[v].keys())
            _succs[k].remove(v);
        edge_count -= _preds[v].size();
        _preds[v].clear();

        is_free[v] = true;
        free_id.push_back(v);
    }

    void clear_edges() {
        _ws.clear();
        for (vert_id v : verts()) {
            _succs[v].clear();
            _preds[v].clear();
        }
        edge_count = 0;
    }
    void clear() {
        _ws.clear();
        _succs.clear();
        _preds.clear();
        is_free.clear();
        free_id.clear();
        free_widx.clear();

        edge_count = 0;
    }

    bool elem(vert_id s, vert_id d) { return _succs[s].elem(d); }

    Wt& edge_val(vert_id s, vert_id d) {
        size_t idx{};
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
        [[nodiscard]] Wt get() const {
            assert(w);
            return *w;
        }
        void operator=(Wt* _w) { w = _w; }
        void operator=(Wt _w) {
            assert(w);
            *w = _w;
        }

      private:
        Wt* w;
    };

    using mut_val_ref_t = mut_val_ref_t;

    bool lookup(vert_id s, vert_id d, mut_val_ref_t* w) {
        size_t idx;
        if (_succs[s].lookup(d, &idx)) {
            (*w) = &(_ws[idx]);
            return true;
        }
        return false;
    }

    void add_edge(vert_id s, Wt w, vert_id d) {
        size_t idx;
        if (!free_widx.empty()) {
            idx = free_widx.back();
            free_widx.pop_back();
            _ws[idx] = w;
        } else {
            idx = _ws.size();
            _ws.push_back(w);
        }

        _succs[s].add(d, idx);
        _preds[d].add(s, idx);
        edge_count++;
    }

    void update_edge(vert_id s, Wt w, vert_id d) {
        size_t idx;
        if (_succs[s].lookup(d, &idx)) {
            _ws[idx] = std::min(_ws[idx], w);
        } else {
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

    // XXX: g cannot be marked const for complicated reasons
    friend std::ostream& operator<<(std::ostream& o, AdaptGraph& g) {
        o << "[|";
        bool first = true;
        for (vert_id v : g.verts()) {
            auto it = g.e_succs(v).begin();
            auto end = g.e_succs(v).end();

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
        return o;
    }

    // Ick. This'll have another indirection on every operation.
    // We'll see what the performance costs are like.
    std::vector<smap_t> _preds;
    std::vector<smap_t> _succs;
    std::vector<Wt> _ws;

    int edge_count;

    std::vector<int> is_free;
    std::vector<vert_id> free_id;
    std::vector<size_t> free_widx;
};
} // namespace crab
#pragma GCC diagnostic pop
