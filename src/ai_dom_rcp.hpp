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

    bool is_of_type(Types t) const {
        for (size_t i=0; i < maps.size(); i++) {
            if (t[i])
                if (!maps[i].is_bot()) return true;
        }
        if (t[t.size() + T_CTX]) if (!ctx.is_bot()) return true;
        if (t[t.size() + T_STACK]) if (!stack.is_bot()) return true;
        if (t[t.size() + T_DATA]) if (!packet.is_bot()) return true;
        if (t[t.size() + T_NUM]) if (!num.is_bot()) return true;
        if (t[t.size() + T_MAP_STRUCT]) if (!fd.is_bot()) return true;
        return false;
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

    static void assume(RCP_domain& then_reg, Types then_type, const RCP_domain& where_reg, Types where_type);
    static void assume(RCP_domain& r, Types t);
    static void assume(RCP_domain& left, Condition::Op op, const RCP_domain& right,
                       Types where_types);

    static void assume(RCP_domain& left, Condition::Op op, const RCP_domain& right) {
        assume(left, op, right, TypeSet{left.maps.size()}.map_struct().flip());
    }

    static void satisfied(const RCP_domain& then_reg, Types then_type, const RCP_domain& where_reg, Types where_type);
    static void satisfied(const RCP_domain& r, Types t);
    static void satisfied(const RCP_domain& left, Condition::Op op, const RCP_domain& right, Types where_types);

    friend std::ostream& operator<<(std::ostream& os, const RCP_domain& a) {
        os << "[";
        for (size_t t=0; t < a.maps.size(); t++) {
            if (!a.maps[t].is_bot()) os << "M" << t << " -> " << a.maps[t] << "; ";
        }
        if (!a.ctx.is_bot()) os << "C -> " << a.ctx << "; ";
        if (!a.packet.is_bot()) os << "P -> " << a.packet << "; ";
        if (!a.stack.is_bot()) os << "S -> " << a.stack << "; ";
        if (!a.num.is_bot()) os << "N -> " << a.num << "; ";
        if (!a.fd.is_bot()) os << "F -> " << a.fd << "";
        os << "]";
        return os;
    }
};
