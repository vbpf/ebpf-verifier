#pragma once

#include <vector>

#include "ai_dom_set.hpp"

#include "spec_assertions.hpp"

class RCP_domain {
    using NumDom = NumDomSet;
    using OffsetDom = OffsetDomSet;

    std::vector<OffsetDom> maps;
    OffsetDom ctx;
    OffsetDom stack;
    OffsetDom packet;
    NumDom num;
    FdSetDom fd;

    Types all() {
        return TypeSet{maps.size()}.all();
    }

    template <typename F>
    void pointwise(const RCP_domain& o, const F& f) {
        pointwise_if(all(), o, f);
    }

    template <typename F>
    void pointwise(const F& f) {
        pointwise_if(all(), f);
    }

    template <typename F>
    void pointwise_if(Types t, const RCP_domain& o, const F& f) {
        assert(t.size() == maps.size() + 5);
        for (size_t i=0; i < maps.size(); i++) {
            if (t[i])
                f(maps[i], o.maps[i]);
        }
        if (t[t.size() + T_CTX]) f(ctx, o.ctx);
        if (t[t.size() + T_STACK]) f(stack, o.stack);
        if (t[t.size() + T_DATA]) f(packet, o.packet);
        if (t[t.size() + T_NUM]) f(num, o.num);
        if (t[t.size() + T_MAP_STRUCT]) f(fd, o.fd);
    }

    template <typename F>
    void pointwise_if(Types t, const F& f) {
        assert(t.size() == maps.size() + 5);
        for (size_t i=0; i < maps.size(); i++) {
            if (t[i])
                f(maps[i]);
        }
        if (t[t.size() + T_CTX]) f(ctx);
        if (t[t.size() + T_STACK])f(stack);
        if (t[t.size() + T_DATA]) f(packet);
        if (t[t.size() + T_NUM]) f(num);
        if (t[t.size() + T_MAP_STRUCT]) f(fd);
    }
    
public:
    RCP_domain with_map(size_t n, const OffsetDomSet& map) const { auto res = *this; res.maps[n] = map; return res; }
    RCP_domain with_maps(const OffsetDomSet& map) const { auto res = *this; for (auto& m : res.maps) m = map; return res; }
    RCP_domain with_ctx(const OffsetDomSet& ctx) const { auto res = *this; res.ctx = ctx; return res; }
    RCP_domain with_stack(const OffsetDomSet& stack) const { auto res = *this; res.stack = stack; return res; }
    RCP_domain with_packet(const OffsetDomSet& packet) const { auto res = *this; res.packet = packet; return res; }
    RCP_domain with_num(const NumDom& num) const { auto res = *this; res.num = num; return res; }
    RCP_domain with_fd(int fd) const { auto res = *this; res.fd.assign(fd); return res; }
    RCP_domain maps_from_fds() const;
    
    void set_mapfd(int mapfd) { fd.assign(mapfd); }

    bool operator==(const RCP_domain& o) const { return maps == o.maps && ctx == o.ctx && stack == o.stack && packet == o.packet && num == o.num && fd == o.fd; }
    bool operator!=(const RCP_domain& o) const { return !((*this) == o); }

    RCP_domain(size_t nmaps) : maps(nmaps), fd{nmaps} {
        // starts as bot
    }
    RCP_domain(size_t nmaps, const Top& _) : maps(nmaps, TOP), ctx{TOP}, stack{TOP}, packet{TOP}, num{TOP}, fd{nmaps, TOP}  {
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

    void operator+=(const RCP_domain& rhs);

    RCP_domain operator+(int n) {
        return *this + RCP_domain(maps.size()).with_num(n);
    }
    
    void operator-=(const RCP_domain& rhs);

    void exec(Bin::Op op, const RCP_domain& o) {
        num.exec(op, o.num);
    }

    static void assume(const RCP_domain& reg, Types t1, const RCP_domain& r2, Types t2);
    static void assume(RCP_domain& reg, Types t);
    static void assume(RCP_domain& left, Condition::Op op, const RCP_domain& right,
                       Types where_types);

    static void assume(RCP_domain& left, Condition::Op op, const RCP_domain& right) {
        assume(left, op, right, left.all());
    }
    static void assume(RCP_domain& reg, const RCP_domain& left_offset, Condition::Op op, const RCP_domain& right,
                       Types where_types) {
        assume(reg, op, right - left_offset, where_types);
    }
    static void assume(RCP_domain& reg, const RCP_domain& left_offset, Condition::Op op, const RCP_domain& right) {
        assume(reg, left_offset, op, right, reg.all());
    }
    static void assume_not(RCP_domain& reg, Types t) {
        assume(reg, t.flip());
    }


    friend std::ostream& operator<<(std::ostream& os, const RCP_domain& a) {
        os << "[";
        for (size_t t=0; t < a.maps.size(); t++) {
            os << "M" << t << " -> " << a.maps[t] << "; ";
        }
        os << "C -> " << a.ctx << "; ";
        os << "P -> " << a.packet << "; ";
        os << "S -> " << a.stack << "; ";
        os << "N -> " << a.num << "; ";
        os << "F -> " << a.fd << "";
        os << "]";
        return os;
    }
};
