// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <memory>

#include "crab_utils/safeint.hpp"
#include "crab_utils/debug.hpp"
// Adaptive sparse-set based weighted graph implementation

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
#endif

namespace crab {

class TreeSMap final {
  public:
    using key_t = uint16_t;
    using val_t = size_t;

  private:
    using col = std::map<key_t, val_t>;
    col map;

  public:
    using elt_t = std::pair<key_t, val_t>;
    using elt_iter_t = col::const_iterator;
    [[nodiscard]] size_t size() const { return map.size(); }

    class key_iter_t {
      public:
        key_iter_t() = default;
        explicit key_iter_t(col::const_iterator _e) : e(_e) {}

        // XXX: to make sure that we always return the same address
        // for the "empty" iterator, otherwise we can trigger
        // undefined behavior.
        inline static std::unique_ptr<key_iter_t> _empty_iter = std::make_unique<key_iter_t>();
        static key_iter_t empty_iterator() {
            return *_empty_iter;
        }

        key_t operator*() const { return e->first; }
        bool operator!=(const key_iter_t& o) const { return e != o.e; }
        key_iter_t& operator++() {
            ++e;
            return *this;
        }

        col::const_iterator e;
    };

    class key_range_t {
      public:
        using iterator = key_iter_t;

        explicit key_range_t(const col& c) : c{c} {}
        [[nodiscard]] size_t size() const { return c.size(); }

        [[nodiscard]] key_iter_t begin() const { return key_iter_t(c.begin()); }
        [[nodiscard]] key_iter_t end() const { return key_iter_t(c.end()); }

        const col& c;
    };

    class elt_range_t {
      public:
        elt_range_t(const col& c) : c{c} {}
        [[nodiscard]] size_t size() const { return c.size(); }

        [[nodiscard]] auto begin() const { return c.begin(); }
        [[nodiscard]] auto end() const { return c.end(); }

        const col& c;
    };

    [[nodiscard]] elt_range_t elts() const { return elt_range_t(map); }
    [[nodiscard]] key_range_t keys() const { return key_range_t(map); }

    [[nodiscard]] bool contains(key_t k) const {
        return map.count(k);
    }

    [[nodiscard]] std::optional<val_t> lookup(key_t k) const {
        auto v = map.find(k);
        if (v != map.end()) {
            return {v->second};
        }
        return {};
    }

    // precondition: k \in S
    void remove(key_t k) {
        map.erase(k);
    }

    // precondition: k \notin S
    void add(key_t k, const val_t& v) {
        map.insert_or_assign(k, v);
    }
    void clear() { map.clear(); }
};

class AdaptGraph final {
    using Weight = safe_i64;  // same as SafeInt64DefaultParams::Wt; previously template
    using smap_t = TreeSMap;

  public:
    using vert_id = unsigned int;
    using Wt = Weight;

    AdaptGraph() : edge_count(0) {}

    AdaptGraph(AdaptGraph&& o) noexcept = default;

    AdaptGraph(const AdaptGraph& o) = default;

    AdaptGraph& operator=(const AdaptGraph& o) = default;

    AdaptGraph& operator=(AdaptGraph&& o) noexcept = default;

    template <class G>
    static AdaptGraph copy(G& o) {
        AdaptGraph g;
        g.growTo(o.size());

        for (vert_id s : o.verts()) {
            for (auto e : o.e_succs(s)) {
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
            Wt val;
        };

        smap_t::elt_iter_t it{};
        const std::vector<Wt>* ws{};

        edge_iter(const smap_t::elt_iter_t& _it, const std::vector<Wt>& _ws) : it(_it), ws(&_ws) {}
        edge_iter(const edge_iter& o) = default;
        edge_iter() = default;

        // XXX: to make sure that we always return the same address
        // for the "empty" iterator, otherwise we can trigger
        // undefined behavior.
        inline static std::unique_ptr<edge_iter> _empty_iter = std::make_unique<edge_iter>();
        static edge_iter empty_iterator() {
            return *_empty_iter;
        }

        edge_ref operator*() const { return edge_ref{it->first, (*ws)[it->second]}; }
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
        const std::vector<Wt>& ws;

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

    [[nodiscard]] edge_range_t e_succs(vert_id v) const { return {_succs[v].elts(), _ws}; }
    [[nodiscard]] edge_range_t e_preds(vert_id v) const { return {_preds[v].elts(), _ws}; }

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
            v = static_cast<vert_id>(_succs.size());
            is_free.push_back(false);
            _succs.emplace_back();
            _preds.emplace_back();
        }

        return v;
    }

    void growTo(size_t v) {
        while (size() < v)
            new_vertex();
    }

    void forget(vert_id v) {
        if (is_free[v])
            return;

        for (const auto& [key, val] : _succs[v].elts()) {
            free_widx.push_back(val);
            _preds[key].remove(v);
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

    bool elem(vert_id s, vert_id d) { return _succs[s].contains(d); }

    Wt& edge_val(vert_id s, vert_id d) {
        return _ws[*_succs[s].lookup(d)];
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

    bool lookup(vert_id s, vert_id d, mut_val_ref_t* w) {
        if (auto idx = _succs[s].lookup(d)) {
            *w = &_ws[*idx];
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
        if (auto idx = _succs[s].lookup(d)) {
            _ws[*idx] = std::min(_ws[*idx], w);
        } else {
            add_edge(s, w, d);
        }
    }

    void set_edge(vert_id s, Wt w, vert_id d) {
        if (auto idx = _succs[s].lookup(d)) {
            _ws[*idx] = w;
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

    size_t edge_count;

    std::vector<int> is_free;
    std::vector<vert_id> free_id;
    std::vector<size_t> free_widx;
};
} // namespace crab
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
