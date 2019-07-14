#include "crab/split_dbm.hpp"


#include "crab/abstract_domain_operators.hpp"
#include "crab/debug.hpp"
#include "crab/stats.hpp"
#include "crab/types.hpp"


namespace crab {
namespace domains {

bool SplitDBM::is_unsat_edge(vert_id x, vert_id y, Wt k) {

    typename graph_t::mut_val_ref_t w;
    if (g.lookup(y, x, &w)) {
        return ((w.get() + k) < Wt(0));
    } else {
        interval_t intv_x = interval_t::top();
        interval_t intv_y = interval_t::top();
        if (g.elem(0, x) || g.elem(x, 0)) {
            intv_x = interval_t(g.elem(x, 0) ? -number_t(g.edge_val(x, 0)) : bound_t::minus_infinity(),
                                g.elem(0, x) ? number_t(g.edge_val(0, x)) : bound_t::plus_infinity());
        }
        if (g.elem(0, y) || g.elem(y, 0)) {
            intv_y = interval_t(g.elem(y, 0) ? -number_t(g.edge_val(y, 0)) : bound_t::minus_infinity(),
                                g.elem(0, y) ? number_t(g.edge_val(0, y)) : bound_t::plus_infinity());
        }
        if (intv_x.is_top() || intv_y.is_top()) {
            return false;
        } else {
            return (!((intv_y - intv_x).lb() <= (number_t)k));
        }
    }
}

SplitDBM::vert_id SplitDBM::get_vert(variable_t v) {
    auto it = vert_map.find(v);
    if (it != vert_map.end())
        return (*it).second;

    vert_id vert(g.new_vertex());
    vert_map.insert(vmap_elt_t(v, vert));
    // Initialize
    assert(vert <= rev_map.size());
    if (vert < rev_map.size()) {
        potential[vert] = Wt(0);
        rev_map[vert] = v;
    } else {
        potential.push_back(Wt(0));
        rev_map.push_back(v);
    }
    vert_map.insert(vmap_elt_t(v, vert));

    assert(vert != 0);

    return vert;
}

SplitDBM::vert_id SplitDBM::get_vert(graph_t &g, vert_map_t &vmap, rev_map_t &rmap, std::vector<Wt> &pot,
                                     variable_t v) {
    auto it = vmap.find(v);
    if (it != vmap.end())
        return (*it).second;

    vert_id vert(g.new_vertex());
    vmap.insert(vmap_elt_t(v, vert));
    // Initialize
    assert(vert <= rmap.size());
    if (vert < rmap.size()) {
        pot[vert] = Wt(0);
        rmap[vert] = v;
    } else {
        pot.push_back(Wt(0));
        rmap.push_back(v);
    }
    vmap.insert(vmap_elt_t(v, vert));

    return vert;
}

void SplitDBM::close_over_edge(vert_id ii, vert_id jj) {
    Wt_min min_op;

    assert(ii != 0 && jj != 0);
    SubGraph<graph_t> g_excl(g, 0);

    Wt c = g_excl.edge_val(ii, jj);

    typename graph_t::mut_val_ref_t w;

    // There may be a cheaper way to do this.
    // GKG: Now implemented.
    std::vector<std::pair<vert_id, Wt>> src_dec;
    for (auto edge : g_excl.e_preds(ii)) {
        vert_id se = edge.vert;
        Wt wt_sij = edge.val + c;

        assert(g_excl.succs(se).begin() != g_excl.succs(se).end());
        if (se != jj) {
            if (g_excl.lookup(se, jj, &w)) {
                if (w.get() <= wt_sij)
                    continue;

                w = wt_sij;
                // g_excl.set_edge(se, wt_sij, jj);
            } else {
                g_excl.add_edge(se, wt_sij, jj);
            }
            src_dec.push_back(std::make_pair(se, edge.val));
        }
    }

    std::vector<std::pair<vert_id, Wt>> dest_dec;
    for (auto edge : g_excl.e_succs(jj)) {
        vert_id de = edge.vert;
        Wt wt_ijd = edge.val + c;
        if (de != ii) {
            if (g_excl.lookup(ii, de, &w)) {
                if (w.get() <= wt_ijd)
                    continue;
                w = wt_ijd;
            } else {
                g_excl.add_edge(ii, wt_ijd, de);
            }
            dest_dec.push_back(std::make_pair(de, edge.val));
        }
    }

    for (auto s_p : src_dec) {
        vert_id se = s_p.first;
        Wt wt_sij = c + s_p.second;
        for (auto d_p : dest_dec) {
            vert_id de = d_p.first;
            Wt wt_sijd = wt_sij + d_p.second;
            if (g.lookup(se, de, &w)) {
                if (w.get() <= wt_sijd)
                    continue;
                w = wt_sijd;
            } else {
                g.add_edge(se, wt_sijd, de);
            }
        }
    }

    // Closure is now updated.
}

void SplitDBM::diffcsts_of_assign(variable_t x, linear_expression_t exp,
                                  /* if true then process the upper
                                     bounds, else the lower bounds */
                                  bool extract_upper_bounds,
                                  /* foreach {v, k} \in diff_csts we have
                                     the difference constraint v - k <= k */
                                  std::vector<std::pair<variable_t, Wt>> &diff_csts) {

    std::optional<variable_t> unbounded_var;
    std::vector<std::pair<variable_t, Wt>> terms;
    bool overflow;

    Wt residual(convert_NtoW(exp.constant(), overflow));
    if (overflow) {
        return;
    }

    for (auto p : exp) {
        Wt coeff(convert_NtoW(p.first, overflow));
        if (overflow) {
            continue;
        }

        variable_t y(p.second);
        if (coeff < Wt(0)) {
            // Can't do anything with negative coefficients.
            bound_t y_val = (extract_upper_bounds ? operator[](y).lb() : operator[](y).ub());

            if (y_val.is_infinite()) {
                return;
            }
            residual += convert_NtoW(*(y_val.number()), overflow) * coeff;
            if (overflow) {
                continue;
            }

        } else {
            bound_t y_val = (extract_upper_bounds ? operator[](y).ub() : operator[](y).lb());

            if (y_val.is_infinite()) {
                if (unbounded_var || coeff != Wt(1)) {
                    return;
                }
                unbounded_var = y;
            } else {
                Wt ymax(convert_NtoW(*(y_val.number()), overflow));
                if (overflow) {
                    continue;
                }
                residual += ymax * coeff;
                terms.push_back({y, ymax});
            }
        }
    }

    if (unbounded_var) {
        // There is exactly one unbounded variable with unit
        // coefficient
        diff_csts.push_back({*unbounded_var, residual});
    } else {
        for (auto p : terms) {
            diff_csts.push_back({p.first, residual - p.second});
        }
    }
}

void SplitDBM::diffcsts_of_lin_leq(const linear_expression_t &exp,
                                   /* difference contraints */
                                   std::vector<diffcst_t> &csts,
                                   /* x >= lb for each {x,lb} in lbs */
                                   std::vector<std::pair<variable_t, Wt>> &lbs,
                                   /* x <= ub for each {x,ub} in ubs */
                                   std::vector<std::pair<variable_t, Wt>> &ubs) {

    Wt unbounded_lbcoeff;
    Wt unbounded_ubcoeff;
    std::optional<variable_t> unbounded_lbvar;
    std::optional<variable_t> unbounded_ubvar;
    bool underflow, overflow;

    Wt exp_ub = -(convert_NtoW(exp.constant(), overflow));
    if (overflow) {
        return;
    }

    // temporary hack
    convert_NtoW(exp.constant() - 1, underflow);
    if (underflow) {
        // We don't like MIN either because the code will compute
        // minus MIN and it will silently overflow.
        return;
    }

    std::vector<std::pair<std::pair<Wt, variable_t>, Wt>> pos_terms, neg_terms;
    for (auto p : exp) {
        Wt coeff(convert_NtoW(p.first, overflow));
        if (overflow) {
            continue;
        }
        if (coeff > Wt(0)) {
            variable_t y(p.second);
            bound_t y_lb = operator[](y).lb();
            if (y_lb.is_infinite()) {
                if (unbounded_lbvar) {
                    return;
                }
                unbounded_lbvar = y;
                unbounded_lbcoeff = coeff;
            } else {
                Wt ymin(convert_NtoW(*(y_lb.number()), overflow));
                if (overflow) {
                    continue;
                }
                exp_ub -= ymin * coeff;
                pos_terms.push_back({{coeff, y}, ymin});
            }
        } else {
            variable_t y(p.second);
            bound_t y_ub = operator[](y).ub();
            if (y_ub.is_infinite()) {
                if (unbounded_ubvar) {
                    return;
                }
                unbounded_ubvar = y;
                unbounded_ubcoeff = -coeff;
            } else {
                Wt ymax(convert_NtoW(*(y_ub.number()), overflow));
                if (overflow) {
                    continue;
                }
                exp_ub -= ymax * coeff;
                neg_terms.push_back({{-coeff, y}, ymax});
            }
        }
    }

    if (unbounded_lbvar) {
        variable_t x(*unbounded_lbvar);
        if (unbounded_ubvar) {
            if (unbounded_lbcoeff != Wt(1) || unbounded_ubcoeff != Wt(1)) {
                return;
            }
            variable_t y(*unbounded_ubvar);
            csts.push_back({{x, y}, exp_ub});
        } else {
            if (unbounded_lbcoeff == Wt(1)) {
                for (auto p : neg_terms) {
                    csts.push_back({{x, p.first.second}, exp_ub - p.second});
                }
            }
            // Add bounds for x
            ubs.push_back({x, exp_ub / unbounded_lbcoeff});
        }
    } else {
        if (unbounded_ubvar) {
            variable_t y(*unbounded_ubvar);
            if (unbounded_ubcoeff == Wt(1)) {
                for (auto p : pos_terms) {
                    csts.push_back({{p.first.second, y}, exp_ub + p.second});
                }
            }
            // Add bounds for y
            lbs.push_back({y, -exp_ub / unbounded_ubcoeff});
        } else {
            for (auto pl : neg_terms) {
                for (auto pu : pos_terms) {
                    csts.push_back({{pu.first.second, pl.first.second}, exp_ub - pl.second + pu.second});
                }
            }
            for (auto pl : neg_terms) {
                lbs.push_back({pl.first.second, -exp_ub / pl.first.first + pl.second});
            }
            for (auto pu : pos_terms) {
                ubs.push_back({pu.first.second, exp_ub / pu.first.first + pu.second});
            }
        }
    }
}

bool SplitDBM::add_linear_leq(const linear_expression_t &exp) {
    CRAB_LOG("zones-split", linear_expression_t exp_tmp(exp); crab::outs() << "Adding: " << exp_tmp << "<= 0"
                                                                           << "\n");
    std::vector<std::pair<variable_t, Wt>> lbs, ubs;
    std::vector<diffcst_t> csts;
    diffcsts_of_lin_leq(exp, csts, lbs, ubs);

    check_potential(g, potential, __LINE__);

    Wt_min min_op;
    typename graph_t::mut_val_ref_t w;
    for (auto p : lbs) {
        CRAB_LOG("zones-split", crab::outs() << p.first << ">=" << p.second << "\n");
        variable_t x(p.first);
        vert_id v = get_vert(p.first);
        if (g.lookup(v, 0, &w) && w.get() <= -p.second)
            continue;
        g.set_edge(v, -p.second, 0);

        if (!repair_potential(v, 0)) {
            set_to_bottom();
            return false;
        }
        check_potential(g, potential, __LINE__);
    }
    for (auto p : ubs) {
        CRAB_LOG("zones-split", crab::outs() << p.first << "<=" << p.second << "\n");
        variable_t x(p.first);
        vert_id v = get_vert(p.first);
        if (g.lookup(0, v, &w) && w.get() <= p.second)
            continue;
        g.set_edge(0, p.second, v);
        if (!repair_potential(0, v)) {
            set_to_bottom();
            return false;
        }
        check_potential(g, potential, __LINE__);
    }

    for (auto diff : csts) {
        CRAB_LOG("zones-split", crab::outs()
                                    << diff.first.first << "-" << diff.first.second << "<=" << diff.second << "\n");

        vert_id src = get_vert(diff.first.second);
        vert_id dest = get_vert(diff.first.first);
        g.update_edge(src, diff.second, dest, min_op);
        if (!repair_potential(src, dest)) {
            set_to_bottom();
            return false;
        }
        check_potential(g, potential, __LINE__);
        close_over_edge(src, dest);
        check_potential(g, potential, __LINE__);
    }
    // Collect bounds
    // GKG: Now done in close_over_edge

    edge_vector delta;
    GrOps::close_after_assign(g, potential, 0, delta);
    GrOps::apply_delta(g, delta);

    check_potential(g, potential, __LINE__);
    // CRAB_WARN("SplitDBM::add_linear_leq not yet implemented.");
    return true;
}
void SplitDBM::add_univar_disequation(variable_t x, number_t n) {
    bool overflow;
    interval_t i = get_interval(x);
    interval_t new_i = linear_interval_solver_impl::trim_interval<interval_t>(i, interval_t(n));
    if (new_i.is_bottom()) {
        set_to_bottom();
    } else if (!new_i.is_top() && (new_i <= i)) {
        vert_id v = get_vert(x);
        typename graph_t::mut_val_ref_t w;
        Wt_min min_op;
        if (new_i.lb().is_finite()) {
            // strenghten lb
            Wt lb_val = convert_NtoW(-(*(new_i.lb().number())), overflow);
            if (overflow) {
                return;
            }

            if (g.lookup(v, 0, &w) && lb_val < w.get()) {
                g.set_edge(v, lb_val, 0);
                if (!repair_potential(v, 0)) {
                    set_to_bottom();
                    return;
                }
                check_potential(g, potential, __LINE__);
                // Update other bounds
                for (auto e : g.e_preds(v)) {
                    if (e.vert == 0)
                        continue;
                    g.update_edge(e.vert, e.val + lb_val, 0, min_op);
                    if (!repair_potential(e.vert, 0)) {
                        set_to_bottom();
                        return;
                    }
                    check_potential(g, potential, __LINE__);
                }
            }
        }
        if (new_i.ub().is_finite()) {
            // strengthen ub
            Wt ub_val = convert_NtoW(*(new_i.ub().number()), overflow);
            if (overflow) {
                return;
            }

            if (g.lookup(0, v, &w) && (ub_val < w.get())) {
                g.set_edge(0, ub_val, v);
                if (!repair_potential(0, v)) {
                    set_to_bottom();
                    return;
                }
                check_potential(g, potential, __LINE__);
                // Update other bounds
                for (auto e : g.e_succs(v)) {
                    if (e.vert == 0)
                        continue;
                    g.update_edge(0, e.val + ub_val, e.vert, min_op);
                    if (!repair_potential(0, e.vert)) {
                        set_to_bottom();
                        return;
                    }
                    check_potential(g, potential, __LINE__);
                }
            }
        }
    }
}

bool SplitDBM::operator<=(SplitDBM o) {
    crab::CrabStats::count(getDomainName() + ".count.leq");
    crab::ScopedCrabStats __st__(getDomainName() + ".leq");

    // cover all trivial cases to avoid allocating a dbm matrix
    if (is_bottom())
        return true;
    else if (o.is_bottom())
        return false;
    else if (o.is_top())
        return true;
    else if (is_top())
        return false;
    else {
        normalize();

        // CRAB_LOG("zones-split", crab::outs() << "operator<=: "<< *this<< "<=?"<< o <<"\n");

        if (vert_map.size() < o.vert_map.size())
            return false;

        typename graph_t::mut_val_ref_t wx;
        typename graph_t::mut_val_ref_t wy;

        // Set up a mapping from o to this.
        std::vector<unsigned int> vert_renaming(o.g.size(), -1);
        vert_renaming[0] = 0;
        for (auto p : o.vert_map) {
            if (o.g.succs(p.second).size() == 0 && o.g.preds(p.second).size() == 0)
                continue;

            auto it = vert_map.find(p.first);
            // We can't have this <= o if we're missing some
            // vertex.
            if (it == vert_map.end())
                return false;
            vert_renaming[p.second] = (*it).second;
            // vert_renaming[(*it).second] = p.second;
        }

        assert(g.size() > 0);
        // GrPerm g_perm(vert_renaming, g);

        for (vert_id ox : o.g.verts()) {
            if (o.g.succs(ox).size() == 0)
                continue;

            assert(vert_renaming[ox] != -1);
            vert_id x = vert_renaming[ox];
            for (auto edge : o.g.e_succs(ox)) {
                vert_id oy = edge.vert;
                assert(vert_renaming[oy] != -1);
                vert_id y = vert_renaming[oy];
                Wt ow = edge.val;

                if (g.lookup(x, y, &wx) && (wx.get() <= ow))
                    continue;

                if (!g.lookup(x, 0, &wx) || !g.lookup(0, y, &wy))
                    return false;
                if (!(wx.get() + wy.get() <= ow))
                    return false;
            }
        }
        return true;
    }
}

SplitDBM SplitDBM::operator|(SplitDBM o) {
    crab::CrabStats::count(getDomainName() + ".count.join");
    crab::ScopedCrabStats __st__(getDomainName() + ".join");

    if (is_bottom() || o.is_top())
        return o;
    else if (is_top() || o.is_bottom())
        return *this;
    else {
        CRAB_LOG("zones-split", crab::outs() << "Before join:\n"
                                             << "DBM 1\n"
                                             << *this << "\n"
                                             << "DBM 2\n"
                                             << o << "\n");

        normalize();
        o.normalize();

        check_potential(g, potential, __LINE__);
        check_potential(o.g, o.potential, __LINE__);

        // Figure out the common renaming, initializing the
        // resulting potentials as we go.
        std::vector<vert_id> perm_x;
        std::vector<vert_id> perm_y;
        std::vector<variable_t> perm_inv;

        std::vector<Wt> pot_rx;
        std::vector<Wt> pot_ry;
        vert_map_t out_vmap;
        rev_map_t out_revmap;
        // Add the zero vertex
        assert(potential.size() > 0);
        pot_rx.push_back(0);
        pot_ry.push_back(0);
        perm_x.push_back(0);
        perm_y.push_back(0);
        out_revmap.push_back(std::nullopt);

        for (auto p : vert_map) {
            auto it = o.vert_map.find(p.first);
            // Variable exists in both
            if (it != o.vert_map.end()) {
                out_vmap.insert(vmap_elt_t(p.first, perm_x.size()));
                out_revmap.push_back(p.first);

                pot_rx.push_back(potential[p.second] - potential[0]);
                // XXX JNL: check this out
                // pot_ry.push_back(o.potential[p.second] - o.potential[0]);
                pot_ry.push_back(o.potential[(*it).second] - o.potential[0]);
                perm_inv.push_back(p.first);
                perm_x.push_back(p.second);
                perm_y.push_back((*it).second);
            }
        }
        unsigned int sz = perm_x.size();

        // Build the permuted view of x and y.
        assert(g.size() > 0);
        GrPerm gx(perm_x, g);
        assert(o.g.size() > 0);
        GrPerm gy(perm_y, o.g);

        // Compute the deferred relations
        graph_t g_ix_ry;
        g_ix_ry.growTo(sz);
        SubGraph<GrPerm> gy_excl(gy, 0);
        for (vert_id s : gy_excl.verts()) {
            for (vert_id d : gy_excl.succs(s)) {
                typename graph_t::mut_val_ref_t ws;
                typename graph_t::mut_val_ref_t wd;
                if (gx.lookup(s, 0, &ws) && gx.lookup(0, d, &wd)) {
                    g_ix_ry.add_edge(s, ws.get() + wd.get(), d);
                }
            }
        }
        // Apply the deferred relations, and re-close.
        edge_vector delta;
        bool is_closed;
        graph_t g_rx(GrOps::meet(gx, g_ix_ry, is_closed));
        check_potential(g_rx, pot_rx, __LINE__);
        if (!is_closed) {
            SubGraph<graph_t> g_rx_excl(g_rx, 0);
            GrOps::close_after_meet(g_rx_excl, pot_rx, gx, g_ix_ry, delta);
            GrOps::apply_delta(g_rx, delta);
        }

        graph_t g_rx_iy;
        g_rx_iy.growTo(sz);

        SubGraph<GrPerm> gx_excl(gx, 0);
        for (vert_id s : gx_excl.verts()) {
            for (vert_id d : gx_excl.succs(s)) {
                typename graph_t::mut_val_ref_t ws;
                typename graph_t::mut_val_ref_t wd;
                // Assumption: gx.mem(s, d) -> gx.edge_val(s, d) <= ranges[var(s)].ub() - ranges[var(d)].lb()
                // That is, if the relation exists, it's at least as strong as the bounds.
                if (gy.lookup(s, 0, &ws) && gy.lookup(0, d, &wd))
                    g_rx_iy.add_edge(s, ws.get() + wd.get(), d);
            }
        }
        delta.clear();
        // Similarly, should use a SubGraph view.
        graph_t g_ry(GrOps::meet(gy, g_rx_iy, is_closed));
        check_potential(g_rx, pot_rx, __LINE__);
        if (!is_closed) {

            SubGraph<graph_t> g_ry_excl(g_ry, 0);
            GrOps::close_after_meet(g_ry_excl, pot_ry, gy, g_rx_iy, delta);
            GrOps::apply_delta(g_ry, delta);
        }

        // We now have the relevant set of relations. Because g_rx and g_ry are closed,
        // the result is also closed.
        Wt_min min_op;
        graph_t join_g(GrOps::join(g_rx, g_ry));

        // Now reapply the missing independent relations.
        // Need to derive vert_ids from lb_up/lb_down, and make sure the vertices exist
        std::vector<vert_id> lb_up;
        std::vector<vert_id> lb_down;
        std::vector<vert_id> ub_up;
        std::vector<vert_id> ub_down;

        typename graph_t::mut_val_ref_t wx;
        typename graph_t::mut_val_ref_t wy;
        for (vert_id v : gx_excl.verts()) {
            if (gx.lookup(0, v, &wx) && gy.lookup(0, v, &wy)) {
                if (wx.get() < wy.get())
                    ub_up.push_back(v);
                if (wy.get() < wx.get())
                    ub_down.push_back(v);
            }
            if (gx.lookup(v, 0, &wx) && gy.lookup(v, 0, &wy)) {
                if (wx.get() < wy.get())
                    lb_down.push_back(v);
                if (wy.get() < wx.get())
                    lb_up.push_back(v);
            }
        }

        for (vert_id s : lb_up) {
            Wt dx_s = gx.edge_val(s, 0);
            Wt dy_s = gy.edge_val(s, 0);
            for (vert_id d : ub_up) {
                if (s == d)
                    continue;

                join_g.update_edge(s, std::max(dx_s + gx.edge_val(0, d), dy_s + gy.edge_val(0, d)), d, min_op);
            }
        }

        for (vert_id s : lb_down) {
            Wt dx_s = gx.edge_val(s, 0);
            Wt dy_s = gy.edge_val(s, 0);
            for (vert_id d : ub_down) {
                if (s == d)
                    continue;

                join_g.update_edge(s, std::max(dx_s + gx.edge_val(0, d), dy_s + gy.edge_val(0, d)), d, min_op);
            }
        }

        // Conjecture: join_g remains closed.

        // Now garbage collect any unused vertices
        for (vert_id v : join_g.verts()) {
            if (v == 0)
                continue;
            if (join_g.succs(v).size() == 0 && join_g.preds(v).size() == 0) {
                join_g.forget(v);
                if (out_revmap[v]) {
                    out_vmap.erase(*(out_revmap[v]));
                    out_revmap[v] = std::nullopt;
                }
            }
        }

        // SplitDBM res(join_range, out_vmap, out_revmap, join_g, join_pot);
        SplitDBM res(std::move(out_vmap), std::move(out_revmap), std::move(join_g), std::move(pot_rx), vert_set_t());
        // join_g.check_adjs();
        CRAB_LOG("zones-split", crab::outs() << "Result join:\n" << res << "\n");

        return res;
    }
}

SplitDBM SplitDBM::operator||(SplitDBM o) {
    crab::CrabStats::count(getDomainName() + ".count.widening");
    crab::ScopedCrabStats __st__(getDomainName() + ".widening");

    if (is_bottom())
        return o;
    else if (o.is_bottom())
        return *this;
    else {
        CRAB_LOG("zones-split", crab::outs() << "Before widening:\n"
                                             << "DBM 1\n"
                                             << *this << "\n"
                                             << "DBM 2\n"
                                             << o << "\n");
        o.normalize();

        // Figure out the common renaming
        std::vector<vert_id> perm_x;
        std::vector<vert_id> perm_y;
        vert_map_t out_vmap;
        rev_map_t out_revmap;
        std::vector<Wt> widen_pot;
        vert_set_t widen_unstable(unstable);

        assert(potential.size() > 0);
        widen_pot.push_back(Wt(0));
        perm_x.push_back(0);
        perm_y.push_back(0);
        out_revmap.push_back(std::nullopt);
        for (auto p : vert_map) {
            auto it = o.vert_map.find(p.first);
            // Variable exists in both
            if (it != o.vert_map.end()) {
                out_vmap.insert(vmap_elt_t(p.first, perm_x.size()));
                out_revmap.push_back(p.first);

                widen_pot.push_back(potential[p.second] - potential[0]);
                perm_x.push_back(p.second);
                perm_y.push_back((*it).second);
            }
        }

        // Build the permuted view of x and y.
        assert(g.size() > 0);
        GrPerm gx(perm_x, g);
        assert(o.g.size() > 0);
        GrPerm gy(perm_y, o.g);

        // Now perform the widening
        std::vector<vert_id> destabilized;
        graph_t widen_g(GrOps::widen(gx, gy, destabilized));
        for (vert_id v : destabilized)
            widen_unstable.insert(v);

        SplitDBM res(std::move(out_vmap), std::move(out_revmap), std::move(widen_g), std::move(widen_pot),
                     std::move(widen_unstable));

        CRAB_LOG("zones-split", crab::outs() << "Result widening:\n" << res << "\n");
        return res;
    }
}
SplitDBM SplitDBM::operator&(SplitDBM o) {
    crab::CrabStats::count(getDomainName() + ".count.meet");
    crab::ScopedCrabStats __st__(getDomainName() + ".meet");

    if (is_bottom() || o.is_bottom())
        return SplitDBM::bottom();
    else if (is_top())
        return o;
    else if (o.is_top())
        return *this;
    else {
        CRAB_LOG("zones-split", crab::outs() << "Before meet:\n"
                                             << "DBM 1\n"
                                             << *this << "\n"
                                             << "DBM 2\n"
                                             << o << "\n");
        normalize();
        o.normalize();

        check_potential(g, potential, __LINE__);
        check_potential(o.g, o.potential, __LINE__);

        // We map vertices in the left operand onto a contiguous range.
        // This will often be the identity map, but there might be gaps.
        vert_map_t meet_verts;
        rev_map_t meet_rev;

        std::vector<vert_id> perm_x;
        std::vector<vert_id> perm_y;
        std::vector<Wt> meet_pi;
        perm_x.push_back(0);
        perm_y.push_back(0);
        meet_pi.push_back(Wt(0));
        meet_rev.push_back(std::nullopt);
        for (auto p : vert_map) {
            vert_id vv = perm_x.size();
            meet_verts.insert(vmap_elt_t(p.first, vv));
            meet_rev.push_back(p.first);

            perm_x.push_back(p.second);
            perm_y.push_back(-1);
            meet_pi.push_back(potential[p.second] - potential[0]);
        }

        // Add missing mappings from the right operand.
        for (auto p : o.vert_map) {
            auto it = meet_verts.find(p.first);

            if (it == meet_verts.end()) {
                vert_id vv = perm_y.size();
                meet_rev.push_back(p.first);

                perm_y.push_back(p.second);
                perm_x.push_back(-1);
                meet_pi.push_back(o.potential[p.second] - o.potential[0]);
                meet_verts.insert(vmap_elt_t(p.first, vv));
            } else {
                perm_y[(*it).second] = p.second;
            }
        }

        // Build the permuted view of x and y.
        assert(g.size() > 0);
        GrPerm gx(perm_x, g);
        assert(o.g.size() > 0);
        GrPerm gy(perm_y, o.g);

        // Compute the syntactic meet of the permuted graphs.
        bool is_closed;
        graph_t meet_g(GrOps::meet(gx, gy, is_closed));

        // Compute updated potentials on the zero-enriched graph
        // vector<Wt> meet_pi(meet_g.size());
        // We've warm-started pi with the operand potentials
        if (!GrOps::select_potentials(meet_g, meet_pi)) {
            // Potentials cannot be selected -- state is infeasible.
            return SplitDBM::bottom();
        }

        if (!is_closed) {
            edge_vector delta;
            SubGraph<graph_t> meet_g_excl(meet_g, 0);
            // GrOps::close_after_meet(meet_g_excl, meet_pi, gx, gy, delta);

            GrOps::close_after_meet(meet_g_excl, meet_pi, gx, gy, delta);

            GrOps::apply_delta(meet_g, delta);

            // Recover updated LBs and UBs.<

            delta.clear();
            GrOps::close_after_assign(meet_g, meet_pi, 0, delta);
            GrOps::apply_delta(meet_g, delta);
        }
        check_potential(meet_g, meet_pi, __LINE__);
        SplitDBM res(std::move(meet_verts), std::move(meet_rev), std::move(meet_g), std::move(meet_pi), vert_set_t());
        CRAB_LOG("zones-split", crab::outs() << "Result meet:\n" << res << "\n");
        return res;
    }
}

void SplitDBM::operator-=(variable_t v) {
    crab::CrabStats::count(getDomainName() + ".count.forget");
    crab::ScopedCrabStats __st__(getDomainName() + ".forget");

    if (is_bottom())
        return;
    normalize();

    auto it = vert_map.find(v);
    if (it != vert_map.end()) {
        CRAB_LOG("zones-split", crab::outs() << "Before forget " << it->second << ": " << g << "\n");
        g.forget(it->second);
        CRAB_LOG("zones-split", crab::outs() << "After: " << g << "\n");
        rev_map[it->second] = std::nullopt;
        vert_map.erase(v);
    }
}

void SplitDBM::operator+=(linear_constraint_t cst) {
    crab::CrabStats::count(getDomainName() + ".count.add_constraints");
    crab::ScopedCrabStats __st__(getDomainName() + ".add_constraints");

    // XXX: we do nothing with unsigned linear inequalities
    if (cst.is_inequality() && cst.is_unsigned()) {
        CRAB_WARN("unsigned inequality ", cst, " skipped by split_dbm domain");
        return;
    }

    if (is_bottom())
        return;
    normalize();

    if (cst.is_tautology())
        return;

    // g.check_adjs();

    if (cst.is_contradiction()) {
        set_to_bottom();
        return;
    }

    if (cst.is_inequality()) {
        if (!add_linear_leq(cst.expression())) {
            set_to_bottom();
        }
        //  g.check_adjs();
        CRAB_LOG("zones-split", crab::outs() << "--- " << cst << "\n" << *this << "\n");
        return;
    }

    if (cst.is_strict_inequality()) {
        // We try to convert a strict to non-strict.
        auto nc = strict_to_non_strict_inequality(cst);
        if (nc.is_inequality()) {
            // here we succeed
            if (!add_linear_leq(nc.expression())) {
                set_to_bottom();
            }
            CRAB_LOG("zones-split", crab::outs() << "--- " << cst << "\n" << *this << "\n");
            return;
        }
    }

    if (cst.is_equality()) {
        linear_expression_t exp = cst.expression();
        if (!add_linear_leq(exp) || !add_linear_leq(-exp)) {
            CRAB_LOG("zones-split", crab::outs() << " ~~> _|_"
                                                 << "\n");
            set_to_bottom();
        }
        // g.check_adjs();
        CRAB_LOG("zones-split", crab::outs() << "--- " << cst << "\n" << *this << "\n");
        return;
    }

    if (cst.is_disequation()) {
        add_disequation(cst.expression());
        return;
    }

    CRAB_WARN("Unhandled constraint ", cst, " by split_dbm");
    CRAB_LOG("zones-split", crab::outs() << "---" << cst << "\n" << *this << "\n");
    return;
}

void SplitDBM::assign(variable_t x, linear_expression_t e) {
    crab::CrabStats::count(getDomainName() + ".count.assign");
    crab::ScopedCrabStats __st__(getDomainName() + ".assign");

    if (is_bottom()) {
        return;
    }

    CRAB_LOG("zones-split", crab::outs() << "Before assign: " << *this << "\n");
    CRAB_LOG("zones-split", crab::outs() << x << ":=" << e << "\n");
    normalize();

    check_potential(g, potential, __LINE__);

    interval_t x_int = eval_interval(e);

    std::optional<Wt> lb_w, ub_w;
    bool overflow;
    if (x_int.lb().is_finite()) {
        lb_w = convert_NtoW(-(*(x_int.lb().number())), overflow);
        if (overflow) {
            operator-=(x);
            CRAB_LOG("zones-split", crab::outs() << "---" << x << ":=" << e << "\n" << *this << "\n");
            return;
        }
    }
    if (x_int.ub().is_finite()) {
        ub_w = convert_NtoW(*(x_int.ub().number()), overflow);
        if (overflow) {
            operator-=(x);
            CRAB_LOG("zones-split", crab::outs() << "---" << x << ":=" << e << "\n" << *this << "\n");
            return;
        }
    }

    bool is_rhs_constant = false;
    // If it's a constant, just assign the interval.

    // JN: it seems that we can only do this if
    // close_bounds_inline is disabled. Otherwise, the meet
    // operator misses some non-redundant edges. Need to
    // investigate more this.
    if (std::optional<number_t> x_n = x_int.singleton()) {
        set(x, *x_n);
        is_rhs_constant = true;
    }

    if (!is_rhs_constant) {
        std::vector<std::pair<variable_t, Wt>> diffs_lb, diffs_ub;
        // Construct difference constraints from the assignment
        diffcsts_of_assign(x, e, diffs_lb, diffs_ub);
        if (diffs_lb.size() > 0 || diffs_ub.size() > 0) {
            bool overflow{};
            Wt e_val = eval_expression(e, overflow);
            if (overflow) {
                operator-=(x);
                return;
            }
            // Allocate a new vertex for x
            vert_id v = g.new_vertex();
            assert(v <= rev_map.size());
            if (v == rev_map.size()) {
                rev_map.push_back(x);
                potential.push_back(potential[0] + e_val);
            } else {
                potential[v] = potential[0] + e_val;
                rev_map[v] = x;
            }

            edge_vector delta;
            for (auto diff : diffs_lb) {
                delta.push_back({{v, get_vert(diff.first)}, -diff.second});
            }

            for (auto diff : diffs_ub) {
                delta.push_back({{get_vert(diff.first), v}, diff.second});
            }

            // apply_delta should be safe here, as x has no edges in G.
            GrOps::apply_delta(g, delta);
            delta.clear();
            SubGraph<graph_t> g_excl(g, 0);
            GrOps::close_after_assign(g_excl, potential, v, delta);
            GrOps::apply_delta(g, delta);

            Wt_min min_op;
            if (lb_w) {
                g.update_edge(v, *lb_w, 0, min_op);
            }
            if (ub_w) {
                g.update_edge(0, *ub_w, v, min_op);
            }
            // Clear the old x vertex
            operator-=(x);
            vert_map.insert(vmap_elt_t(x, v));
        } else {
            set(x, x_int);
        }
    }

    // CRAB_WARN("DBM only supports a cst or var on the rhs of assignment");
    // this->operator-=(x);
    // g.check_adjs();

    check_potential(g, potential, __LINE__);
    CRAB_LOG("zones-split", crab::outs() << "---" << x << ":=" << e << "\n" << *this << "\n");
}

void SplitDBM::rename(const variable_vector_t &from, const variable_vector_t &to) {
    crab::CrabStats::count(getDomainName() + ".count.rename");
    crab::ScopedCrabStats __st__(getDomainName() + ".rename");

    if (is_top() || is_bottom())
        return;

    // renaming vert_map by creating a new vert_map since we are
    // modifying the keys.
    // rev_map is modified in-place since we only modify values.
    CRAB_LOG("zones-split", crab::outs() << "Replacing {"; for (auto v
                                                                : from) crab::outs()
                                                           << v << ";";
             crab::outs() << "} with "; for (auto v
                                             : to) crab::outs()
                                        << v << ";";
             crab::outs() << "}:\n"; crab::outs() << *this << "\n";);

    vert_map_t new_vert_map;
    for (auto kv : vert_map) {
        ptrdiff_t pos = std::distance(from.begin(), std::find(from.begin(), from.end(), kv.first));
        if (pos < from.size()) {
            variable_t new_v(to[pos]);
            new_vert_map.insert(vmap_elt_t(new_v, kv.second));
            rev_map[kv.second] = new_v;
        } else {
            new_vert_map.insert(kv);
        }
    }
    std::swap(vert_map, new_vert_map);

    CRAB_LOG("zones-split", crab::outs() << "RESULT=" << *this << "\n");
}

void SplitDBM::extract(const variable_t &x, linear_constraint_system_t &csts, bool only_equalities) {
    crab::CrabStats::count(getDomainName() + ".count.extract");
    crab::ScopedCrabStats __st__(getDomainName() + ".extract");

    normalize();
    if (is_bottom()) {
        return;
    }

    auto it = vert_map.find(x);
    if (it != vert_map.end()) {
        vert_id s = (*it).second;
        if (rev_map[s]) {
            variable_t vs = *rev_map[s];
            SubGraph<graph_t> g_excl(g, 0);
            for (vert_id d : g_excl.verts()) {
                if (rev_map[d]) {
                    variable_t vd = *rev_map[d];
                    // We give priority to equalities since some domains
                    // might not understand inequalities
                    if (g_excl.elem(s, d) && g_excl.elem(d, s) && g_excl.edge_val(s, d) == Wt(0) &&
                        g_excl.edge_val(d, s) == Wt(0)) {
                        linear_constraint_t cst(linear_expression_t(vs) == vd);
                        csts += cst;
                    } else {
                        if (!only_equalities && g_excl.elem(s, d)) {
                            linear_constraint_t cst(vd - vs <= number_t(g_excl.edge_val(s, d)));
                            csts += cst;
                        }
                        if (!only_equalities && g_excl.elem(d, s)) {
                            linear_constraint_t cst(vs - vd <= number_t(g_excl.edge_val(d, s)));
                            csts += cst;
                        }
                    }
                }
            }
        }
    }
}

SplitDBM SplitDBM::operator&&(SplitDBM o) {
    crab::CrabStats::count(getDomainName() + ".count.narrowing");
    crab::ScopedCrabStats __st__(getDomainName() + ".narrowing");

    if (is_bottom() || o.is_bottom())
        return SplitDBM::bottom();
    else if (is_top())
        return o;
    else {
        CRAB_LOG("zones-split", crab::outs() << "Before narrowing:\n"
                                             << "DBM 1\n"
                                             << *this << "\n"
                                             << "DBM 2\n"
                                             << o << "\n");

        // FIXME: Implement properly
        // Narrowing as a no-op should be sound.
        normalize();
        SplitDBM res(*this);

        CRAB_LOG("zones-split", crab::outs() << "Result narrowing:\n" << res << "\n");
        return res;
    }
}

void SplitDBM::normalize() {
    crab::CrabStats::count(getDomainName() + ".count.normalize");
    crab::ScopedCrabStats __st__(getDomainName() + ".normalize");

    // dbm_canonical(_dbm);
    // Always maintained in normal form, except for widening
    if (unstable.size() == 0)
        return;

    edge_vector delta;
    // GrOps::close_after_widen(g, potential, vert_set_wrap_t(unstable), delta);
    // GKG: Check
    SubGraph<graph_t> g_excl(g, 0);
    GrOps::close_after_widen(g_excl, potential, vert_set_wrap_t(unstable), delta);
    // Retrive variable bounds
    GrOps::close_after_assign(g, potential, 0, delta);

    GrOps::apply_delta(g, delta);

    unstable.clear();
}
void SplitDBM::set(variable_t x, interval_t intv) {
    crab::CrabStats::count(getDomainName() + ".count.assign");
    crab::ScopedCrabStats __st__(getDomainName() + ".assign");

    if (is_bottom())
        return;

    if (intv.is_bottom()) {
        set_to_bottom();
        return;
    }

    this->operator-=(x);

    if (intv.is_top()) {
        return;
    }

    vert_id v = get_vert(x);
    bool overflow;
    if (intv.ub().is_finite()) {
        Wt ub = convert_NtoW(*(intv.ub().number()), overflow);
        if (overflow) {
            return;
        }
        potential[v] = potential[0] + ub;
        g.set_edge(0, ub, v);
    }
    if (intv.lb().is_finite()) {
        Wt lb = convert_NtoW(*(intv.lb().number()), overflow);
        if (overflow) {
            return;
        }
        potential[v] = potential[0] + lb;
        g.set_edge(v, -lb, 0);
    }
}
void SplitDBM::apply(operation_t op, variable_t x, variable_t y, variable_t z) {
    crab::CrabStats::count(getDomainName() + ".count.apply");
    crab::ScopedCrabStats __st__(getDomainName() + ".apply");

    if (is_bottom()) {
        return;
    }

    normalize();

    switch (op) {
    case OP_ADDITION: assign(x, y + z); return;
    case OP_SUBTRACTION: assign(x, y - z); return;
    // For the rest of operations, we fall back on intervals.
    case OP_MULTIPLICATION: set(x, get_interval(y) * get_interval(z)); break;
    case OP_SDIV: set(x, get_interval(y) / get_interval(z)); break;
    case OP_UDIV: set(x, get_interval(y).UDiv(get_interval(z))); break;
    case OP_SREM: set(x, get_interval(y).SRem(get_interval(z))); break;
    case OP_UREM: set(x, get_interval(y).URem(get_interval(z))); break;
    default: CRAB_ERROR("Operation ", op, " not supported");
    }

    CRAB_LOG("zones-split", crab::outs() << "---" << x << ":=" << y << op << z << "\n" << *this << "\n");
}
void SplitDBM::apply(operation_t op, variable_t x, variable_t y, number_t k) {
    crab::CrabStats::count(getDomainName() + ".count.apply");
    crab::ScopedCrabStats __st__(getDomainName() + ".apply");

    if (is_bottom()) {
        return;
    }

    normalize();

    switch (op) {
    case OP_ADDITION: assign(x, y + k); return;
    case OP_SUBTRACTION: assign(x, y - k); return;
    case OP_MULTIPLICATION: assign(x, k * y); return;
    // For the rest of operations, we fall back on intervals.
    case OP_SDIV: set(x, get_interval(y) / interval_t(k)); break;
    case OP_UDIV: set(x, get_interval(y).UDiv(interval_t(k))); break;
    case OP_SREM: set(x, get_interval(y).SRem(interval_t(k))); break;
    case OP_UREM: set(x, get_interval(y).URem(interval_t(k))); break;
    default: CRAB_ERROR("Operation ", op, " not supported");
    }

    CRAB_LOG("zones-split", crab::outs() << "---" << x << ":=" << y << op << k << "\n" << *this << "\n");
}

void SplitDBM::apply(bitwise_operation_t op, variable_t x, variable_t y, variable_t z) {
    crab::CrabStats::count(getDomainName() + ".count.apply");
    crab::ScopedCrabStats __st__(getDomainName() + ".apply");

    // Convert to intervals and perform the operation
    normalize();
    this->operator-=(x);

    interval_t yi = operator[](y);
    interval_t zi = operator[](z);
    interval_t xi = interval_t::bottom();
    switch (op) {
    case OP_AND: xi = yi.And(zi); break;
    case OP_OR: xi = yi.Or(zi); break;
    case OP_XOR: xi = yi.Xor(zi); break;
    case OP_SHL: xi = yi.Shl(zi); break;
    case OP_LSHR: xi = yi.LShr(zi); break;
    case OP_ASHR: xi = yi.AShr(zi); break;
    default: CRAB_ERROR("DBM: unreachable");
    }
    set(x, xi);
}

void SplitDBM::apply(bitwise_operation_t op, variable_t x, variable_t y, number_t k) {
    crab::CrabStats::count(getDomainName() + ".count.apply");
    crab::ScopedCrabStats __st__(getDomainName() + ".apply");

    // Convert to intervals and perform the operation
    normalize();
    interval_t yi = operator[](y);
    interval_t zi(k);
    interval_t xi = interval_t::bottom();

    switch (op) {
    case OP_AND: xi = yi.And(zi); break;
    case OP_OR: xi = yi.Or(zi); break;
    case OP_XOR: xi = yi.Xor(zi); break;
    case OP_SHL: xi = yi.Shl(zi); break;
    case OP_LSHR: xi = yi.LShr(zi); break;
    case OP_ASHR: xi = yi.AShr(zi); break;
    default: CRAB_ERROR("DBM: unreachable");
    }
    set(x, xi);
}
void SplitDBM::project(const variable_vector_t &variables) {
    crab::CrabStats::count(getDomainName() + ".count.project");
    crab::ScopedCrabStats __st__(getDomainName() + ".project");

    if (is_bottom() || is_top()) {
        return;
    }
    if (variables.empty()) {
        return;
    }

    normalize();

    std::vector<bool> save(rev_map.size(), false);
    for (auto x : variables) {
        auto it = vert_map.find(x);
        if (it != vert_map.end())
            save[(*it).second] = true;
    }

    for (vert_id v = 0; v < rev_map.size(); v++) {
        if (!save[v] && rev_map[v]) {
            operator-=((*rev_map[v]));
        }
    }
}

void SplitDBM::forget(const variable_vector_t &variables) {
    crab::CrabStats::count(getDomainName() + ".count.forget");
    crab::ScopedCrabStats __st__(getDomainName() + ".forget");

    if (is_bottom() || is_top()) {
        return;
    }

    for (auto v : variables) {
        auto it = vert_map.find(v);
        if (it != vert_map.end()) {
            operator-=(v);
        }
    }
}

void SplitDBM::expand(variable_t x, variable_t y) {
    crab::CrabStats::count(getDomainName() + ".count.expand");
    crab::ScopedCrabStats __st__(getDomainName() + ".expand");

    if (is_bottom() || is_top()) {
        return;
    }

    CRAB_LOG("zones-split", crab::outs() << "Before expand " << x << " into " << y << ":\n" << *this << "\n");

    auto it = vert_map.find(y);
    if (it != vert_map.end()) {
        CRAB_ERROR("split_dbm expand operation failed because y already exists");
    }

    vert_id ii = get_vert(x);
    vert_id jj = get_vert(y);

    for (auto edge : g.e_preds(ii)) {
        g.add_edge(edge.vert, edge.val, jj);
    }

    for (auto edge : g.e_succs(ii)) {
        g.add_edge(jj, edge.val, edge.vert);
    }

    potential[jj] = potential[ii];

    CRAB_LOG("zones-split", crab::outs() << "After expand " << x << " into " << y << ":\n" << *this << "\n");
}
bool SplitDBM::is_unsat(linear_constraint_t cst) {
    if (is_bottom() || cst.is_contradiction()) {
        return true;
    }

    if (is_top() || cst.is_tautology()) {
        return false;
    }

    std::vector<std::pair<variable_t, Wt>> lbs, ubs;
    std::vector<diffcst_t> diffcsts;

    if (cst.is_inequality()) {
        linear_expression_t exp = cst.expression();
        diffcsts_of_lin_leq(exp, diffcsts, lbs, ubs);
    } else if (cst.is_strict_inequality()) {
        auto nc = strict_to_non_strict_inequality(cst);
        if (nc.is_inequality()) {
            linear_expression_t exp = nc.expression();
            diffcsts_of_lin_leq(exp, diffcsts, lbs, ubs);
        } else {
            // we couldn't convert the strict into a non-strict
            return false;
        }
    } else if (cst.is_equality()) {
        linear_expression_t exp = cst.expression();
        diffcsts_of_lin_leq(exp, diffcsts, lbs, ubs);
        diffcsts_of_lin_leq(-exp, diffcsts, lbs, ubs);
    } else {
        return false;
    }

    // check difference constraints
    for (auto diffcst : diffcsts) {
        variable_t x = diffcst.first.first;
        variable_t y = diffcst.first.second;
        Wt k = diffcst.second;
        if (is_unsat_edge(get_vert(y), get_vert(x), k)) {
            return true;
        }
    }

    // check interval constraints
    for (auto ub : ubs) {
        if (is_unsat_edge(0, get_vert(ub.first), ub.second)) {
            return true;
        }
    }
    for (auto lb : lbs) {
        if (is_unsat_edge(get_vert(lb.first), 0, -lb.second)) {
            return true;
        }
    }

    return false;
}

void SplitDBM::write(crab_os &o) {

    normalize();

    if (is_bottom()) {
        o << "_|_";
        return;
    } else if (is_top()) {
        o << "{}";
        return;
    } else {
        // Intervals
        bool first = true;
        o << "{";
        // Extract all the edges
        SubGraph<graph_t> g_excl(g, 0);
        for (vert_id v : g_excl.verts()) {
            if (!rev_map[v])
                continue;
            if (!g.elem(0, v) && !g.elem(v, 0))
                continue;
            interval_t v_out = interval_t(g.elem(v, 0) ? -number_t(g.edge_val(v, 0)) : bound_t::minus_infinity(),
                                          g.elem(0, v) ? number_t(g.edge_val(0, v)) : bound_t::plus_infinity());

            if (first)
                first = false;
            else
                o << ", ";
            o << *(rev_map[v]) << " -> " << v_out;
        }

        for (vert_id s : g_excl.verts()) {
            if (!rev_map[s])
                continue;
            variable_t vs = *rev_map[s];
            for (vert_id d : g_excl.succs(s)) {
                if (!rev_map[d])
                    continue;
                variable_t vd = *rev_map[d];

                if (first)
                    first = false;
                else
                    o << ", ";
                o << vd << "-" << vs << "<=" << g_excl.edge_val(s, d);
            }
        }
        o << "}";

        // linear_constraint_system_t inv = to_linear_constraint_system();
        // o << inv;
    }
}
linear_constraint_system_t SplitDBM::to_linear_constraint_system() {
    crab::CrabStats::count(getDomainName() + ".count.to_linear_constraints");
    crab::ScopedCrabStats __st__(getDomainName() + ".to_linear_constraints");

    normalize();

    linear_constraint_system_t csts;

    if (is_bottom()) {
        csts += linear_constraint_t::get_false();
        return csts;
    }

    // Extract all the edges

    SubGraph<graph_t> g_excl(g, 0);

    for (vert_id v : g_excl.verts()) {
        if (!rev_map[v])
            continue;
        if (g.elem(v, 0)) {
            csts += linear_constraint_t(linear_expression_t(*rev_map[v]) >= -number_t(g.edge_val(v, 0)));
        }
        if (g.elem(0, v))
            csts += linear_constraint_t(linear_expression_t(*rev_map[v]) <= number_t(g.edge_val(0, v)));
    }

    for (vert_id s : g_excl.verts()) {
        if (!rev_map[s])
            continue;
        variable_t vs = *rev_map[s];
        for (vert_id d : g_excl.succs(s)) {
            if (!rev_map[d])
                continue;
            variable_t vd = *rev_map[d];
            csts += linear_constraint_t(vd - vs <= number_t(g_excl.edge_val(s, d)));
        }
    }
    return csts;
}

template <class AbsDom>
class BackwardAssignOps {
  public:

    /*
     * Backward x := e
     *
     *  General case:
     *   if x does not appear in e
     *      1) add constraint x = e
     *      2) forget x
     *   else
     *      1) add new variable x'
     *      2) add constraint x = e[x'/x]
     *      3) forget x
     *      4) rename x' as x
     *
     *  Invertible operation (y can be equal to x):
     *    x = y + k <--> y = x - k
     *    x = y - k <--> y = x + k
     *    x = y * k <--> y = x / k  if (k != 0)
     *    x = y / k <--> y = x * k  if (k != 0)
     *
     *  Fallback case:
     *   forget(x)
     **/

    // x := e
    static void assign(AbsDom &dom, variable_t x, linear_expression_t e, AbsDom inv) {
        crab::CrabStats::count(AbsDom::getDomainName() + ".count.backward_assign");
        crab::ScopedCrabStats __st__(AbsDom::getDomainName() + ".backward_assign");

        if (dom.is_bottom())
            return;

        if (e.variables() >= x) {
            auto &vfac = x.name().get_var_factory();
            variable_t old_x(vfac.get(), x.get_type());
            std::map<variable_t, variable_t> renaming_map;
            renaming_map.insert({x, old_x});
            linear_expression_t renamed_e = e.rename(renaming_map);
            dom += linear_constraint_t(renamed_e - x, linear_constraint_t::EQUALITY);
            dom -= x;
            dom.rename({old_x}, {x});
        } else {
            dom += linear_constraint_t(e - x, linear_constraint_t::EQUALITY);
            dom -= x;
        }
        dom = dom & inv;
    }

    // x := y op k
    static void apply(AbsDom &dom, operation_t op, variable_t x, variable_t y, number_t k, AbsDom inv) {
        crab::CrabStats::count(AbsDom::getDomainName() + ".count.backward_apply");
        crab::ScopedCrabStats __st__(AbsDom::getDomainName() + ".backward_apply");

        if (dom.is_bottom()) {
            return;
        }

        CRAB_LOG("backward", crab::outs() << x << ":=" << y << " " << op << " " << k << "\n"
                                          << "BEFORE " << dom << "\n";);

        switch (op) {
        case OP_ADDITION:
            dom.apply(OP_SUBTRACTION, y, x, k);
            if (!(x == y)) {
                dom -= x;
            }
            break;
        case OP_SUBTRACTION:
            dom.apply(OP_ADDITION, y, x, k);
            if (!(x == y)) {
                dom -= x;
            }
            break;
        case OP_MULTIPLICATION:
            if (k != 0) {
                dom.apply(OP_SDIV, y, x, k);
                if (!(x == y)) {
                    dom -= x;
                }
            } else {
                dom -= x;
            }
            break;
        case OP_SDIV:
            if (k != 0) {
                dom.apply(OP_MULTIPLICATION, y, x, k);
                if (!(x == y)) {
                    dom -= x;
                }
            } else {
                dom -= x;
            }
            break;
        case OP_UDIV:
        case OP_SREM:
        case OP_UREM:
        default:
            CRAB_WARN("backwards x:= y ", op, " k is not implemented");
            dom -= x;
        }

        dom = dom & inv;

        CRAB_LOG("backward", crab::outs() << "AFTER " << dom << "\n");
        return;
    }

    // x = y op z
    static void apply(AbsDom &dom, operation_t op, variable_t x, variable_t y, variable_t z, AbsDom inv) {
        crab::CrabStats::count(AbsDom::getDomainName() + ".count.backward_apply");
        crab::ScopedCrabStats __st__(AbsDom::getDomainName() + ".backward_apply");

        if (dom.is_bottom()) {
            return;
        }

        CRAB_LOG("backward", crab::outs() << x << ":=" << y << " " << op << " " << z << "\n"
                                          << "BEFORE " << dom << "\n";);

        switch (op) {
        case OP_ADDITION:
            assign(dom, x, linear_expression_t(y + z), inv);
            break;
        case OP_SUBTRACTION:
            assign(dom, x, linear_expression_t(y - z), inv);
            break;
        case OP_MULTIPLICATION:
        case OP_SDIV:
        case OP_UDIV:
        case OP_SREM:
        case OP_UREM:
            CRAB_WARN("backwards x = y ", op, " z not implemented");
            dom -= x;
            break;
        }
        dom = dom & inv;
        CRAB_LOG("backward", crab::outs() << "AFTER " << dom << "\n");
    }
};

void SplitDBM::backward_assign(variable_t x, linear_expression_t e, SplitDBM inv) {
    crab::domains::BackwardAssignOps<SplitDBM>::assign(*this, x, e, inv);
}

void SplitDBM::backward_apply(operation_t op, variable_t x, variable_t y, number_t z, SplitDBM inv) {
    crab::domains::BackwardAssignOps<SplitDBM>::apply(*this, op, x, y, z, inv);
}

void SplitDBM::backward_apply(operation_t op, variable_t x, variable_t y, variable_t z, SplitDBM inv) {
    crab::domains::BackwardAssignOps<SplitDBM>::apply(*this, op, x, y, z, inv);
}
} // namespace domains
} // namespace crab