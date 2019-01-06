#pragma once

#include <vector>
#include <array>

#include "ai_dom_set.hpp"

#include "spec_assertions.hpp"
#include "spec_type_descriptors.hpp"

class RCP_domain {
    using NumDom = NumDomSet;
    using OffsetDom = OffsetDomSet;

    std::array<OffsetDom, NMAPS> maps;
    OffsetDom ctx;
    OffsetDom stack;
    OffsetDom packet;
    NumDom num;
    FdSetDom fd;

    template <typename F>
    void pointwise(const RCP_domain& o, const F& f) {
        pointwise_if(TypeSet::all, o, f);
    }

    template <typename F>
    void pointwise(const F& f) {
        pointwise_if(TypeSet::all, f);
    }

    template <typename P>
    bool pointwise_all(Types t, const P& p) const {
        for (size_t i=0; i < maps.size(); i++) {
            if (t[i] && !p(maps[i])) return false;
        }
        if (t[t.size() + T_CTX]) if (!p(ctx)) return false;
        if (t[t.size() + T_STACK]) if (!p(stack)) return false;
        if (t[t.size() + T_DATA]) if (!p(packet)) return false;
        if (t[t.size() + T_NUM]) if (!p(num)) return false;
        if (t[t.size() + T_FD]) if (!p(fd)) return false;
        return true;
    }

    template <typename P>
    bool pointwise_all_pairs(Types t, const RCP_domain& o, const P& p) const {
        for (size_t i=0; i < maps.size(); i++) {
            if (t[i] && !p(maps[i], o.maps[i])) return false;
        }
        if (t[t.size() + T_CTX]) if (!p(ctx, o.ctx)) return false;
        if (t[t.size() + T_STACK]) if (!p(stack, o.stack)) return false;
        if (t[t.size() + T_DATA]) if (!p(packet, o.packet)) return false;
        if (t[t.size() + T_NUM]) if (!p(num, o.num)) return false;
        if (t[t.size() + T_FD]) if (!p(fd, o.fd)) return false;
        return true;
    }

    bool is_of_type(Types t) const {
        // not-not-of-type
        return pointwise_all(~t, [](const auto& a) { return a.is_bot(); });
    }

    template <typename F>
    void pointwise_if(Types t, const RCP_domain& o, const F& f) {
        for (size_t i=0; i < maps.size(); i++) {
            if (t[i])
                f(maps[i], o.maps[i]);
        }
        if (t[t.size() + T_CTX]) f(ctx, o.ctx);
        if (t[t.size() + T_STACK]) f(stack, o.stack);
        if (t[t.size() + T_DATA]) f(packet, o.packet);
        if (t[t.size() + T_NUM]) f(num, o.num);
        if (t[t.size() + T_FD]) f(fd, o.fd);
    }

    template <typename F>
    void pointwise_if(Types t, const F& f) {
        for (size_t i=0; i < maps.size(); i++) {
            if (t[i])
                f(maps[i]);
        }
        if (t[t.size() + T_CTX]) f(ctx);
        if (t[t.size() + T_STACK]) f(stack);
        if (t[t.size() + T_DATA]) f(packet);
        if (t[t.size() + T_NUM]) f(num);
        if (t[t.size() + T_FD]) f(fd);
    }

public:
    RCP_domain with_map(size_t n, const OffsetDom& map) const { auto res = *this; res.maps[n] = map; return res; }
    RCP_domain with_maps(const OffsetDom& map) const { auto res = *this; for (auto& m : res.maps) m = map; return res; }
    RCP_domain with_ctx(const OffsetDom& ctx) const { auto res = *this; res.ctx = ctx; return res; }
    RCP_domain with_stack(const OffsetDom& stack) const { auto res = *this; res.stack = stack; return res; }
    RCP_domain with_packet(const OffsetDom& packet) const { auto res = *this; res.packet = packet; return res; }
    RCP_domain with_num(const NumDom& num) const { auto res = *this; res.num = num; return res; }
    RCP_domain with_fd(int fd) const { auto res = *this; res.fd.assign(fd); return res; }
    RCP_domain with_fd(Top t) const { auto res = *this; res.fd.havoc(); return res; }
    FdSetDom get_fd() { return fd; };
    
    void set_mapfd(int mapfd) {
        assert(mapfd >= 0);
        assert(mapfd < fd.fds.size());
        fd.assign(mapfd);
    }

    RCP_domain map_lookup_elem(const std::vector<map_def> map_defs) const {
        RCP_domain res;
        for (size_t i=0; i < map_defs.size(); i++) {
            if (fd.fds[i]) {
                auto def = map_defs.at(i);
                if (def.type == MapType::ARRAY_OF_MAPS
                    || def.type == MapType::HASH_OF_MAPS) {
                    res = res.with_fd(def.inner_map_fd);
                } else {
                    res = res.with_map(i, 0);
                }
            }
        }
        return res.with_num(0);
    }

    // idea: pass responsibilities to these memory domain instead of extraction
    OffsetDom get_ctx() const {
        return ctx;
    }
    OffsetDom get_stack() const {
        return stack;
    }
    bool maybe_packet() const {
        return !packet.is_bot();
    }
    bool maybe_map() const {
        return std::any_of(maps.cbegin(), maps.cend(), [](const auto& m) { return !m.is_bot(); });
    }
    NumDom get_num() const {
        return num;
    }
    bool must_be_num() const {
        return with_num({}).is_bot();
    }

   bool operator==(const RCP_domain& o) const {
        return pointwise_all_pairs(TypeSet::all, o,
            [](const auto& a, const auto& b){ return a == b; }); 
    }

    bool operator!=(const RCP_domain& o) const { return !((*this) == o); }

    RCP_domain() {
        // starts as bot
    }
    RCP_domain(const Top& _) : ctx{TOP}, stack{TOP}, packet{TOP}, num{TOP}, fd{TOP}  {
        for (auto& v : maps) v.havoc();
    }

    void operator|=(const RCP_domain& o) {
        pointwise(o, [](auto& a, const auto& b) { a |= b; });
    }

    void operator&=(const RCP_domain& o) {
        pointwise(o, [](auto& a, const auto& b) { a &= b; });
    }

    void havoc() {
        pointwise([](auto& a) { a.havoc(); });
    }

    void to_bot() {
        pointwise([](auto& a) { a.to_bot(); });
    }

    bool is_bot() const {
        return pointwise_all(TypeSet::all, [](const auto& f) { return f.is_bot(); });
    }
    bool is_top() const {
        return pointwise_all(TypeSet::all, [](const auto& f) { return f.is_top(); });
    }

    void operator+=(const RCP_domain& rhs);

    RCP_domain operator+(int n) const {
        return *this + RCP_domain{}.with_num(n);
    }
    
    void operator-=(const RCP_domain& rhs);

    void exec(Bin::Op op, const RCP_domain& o) {
        num.exec(op, o.num);
    }

    static void assume(RCP_domain& then_reg, Types then_type, const RCP_domain& where_reg, Types where_type);
    static void assume(RCP_domain& r, Types t);
    static void assume(RCP_domain& left, Condition::Op op, const RCP_domain& right,
                       Types where_types);

    static void assume(RCP_domain& left, Condition::Op op, const RCP_domain& right) {
        if (op == Condition::Op::EQ || op == Condition::Op::NE)
            assume(left, op, right, TypeSet::all);
        else
            assume(left, op, right, TypeSet::nonfd);
    }

    static bool satisfied(const RCP_domain& then_reg, Types then_type, const RCP_domain& where_reg, Types where_type);
    static bool satisfied(const RCP_domain& r, Types t);
    static bool satisfied(const RCP_domain& left, Condition::Op op, const RCP_domain& right, Types where_types);

    RCP_domain zero() const {
        RCP_domain res = *this;
        res.pointwise([](auto& f){ if (!f.is_bot()) f = {0}; });
        return res;
    }

    friend std::ostream& operator<<(std::ostream& os, const RCP_domain& a) {
        if (a.is_top()) return os << "T";
        if (a.with_fd(TOP).is_top()) return os << "NON-FD";
        os << "[";
        for (size_t t=0; t < a.maps.size(); t++) {
            if (!a.maps[t].is_bot()) os << "MAP" << t << "->" << a.maps[t] << "; ";
        }
        if (!a.ctx.is_bot()) os << "CTX->" << a.ctx << "; ";
        if (!a.packet.is_bot()) os << "PKT->" << a.packet << "; ";
        if (!a.stack.is_bot()) os << "STK->" << a.stack << "; ";
        if (!a.num.is_bot()) os << "NUM->" << a.num << "; ";
        if (!a.fd.is_bot()) os << "FD->" << a.fd << "";
        os << "]";
        return os;
    }
};
