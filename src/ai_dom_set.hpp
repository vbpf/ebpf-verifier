#pragma once

#include <vector>

#include <boost/dynamic_bitset.hpp>

#include "asm_syntax.hpp"

constexpr class Top { } TOP;

struct FdSetDom {
    using This = FdSetDom;

    boost::dynamic_bitset<> fds;
    
    FdSetDom(size_t nmaps) : fds{nmaps} { }
    FdSetDom(size_t nmaps, const Top& _) : fds{nmaps} { havoc(); }
    FdSetDom(const boost::dynamic_bitset<>& fds) : fds{fds} { }

    void assign(int mapfd) {
        fds.reset();
        fds.set(mapfd);
    }

    bool is_bot() const { return fds.none(); }
    void havoc() { fds.set(); };
    void to_bot() { fds.reset(); };

    void operator|=(const FdSetDom& o) { fds |= o.fds; }
    void operator&=(const FdSetDom& o) { fds &= o.fds; }

    bool operator==(const FdSetDom& o) const { return fds == o.fds; };

    friend std::ostream& operator<<(std::ostream& os, const FdSetDom& a) {
        return os << a.fds;
    }

    void assume(Condition::Op op, const This& b) { 

    }
};

class NumDomSet {
    using This = NumDomSet;
    // Naive set implementation
    bool top{};
    std::vector<uint64_t> elems;

    static NumDomSet make_top() { NumDomSet res; res.havoc(); return res; }
    static NumDomSet from_elems(std::vector<uint64_t>&& elems);
public:
    template <typename ...Args>
    NumDomSet(Args... elems) : elems{static_cast<uint64_t>(elems)...} { }

    NumDomSet(const Top& _) : top{true} { }

    bool is_bot() const { return elems.empty(); }
    void to_bot() { elems.clear(); top = false; }
    void havoc() { elems.clear(); top = true; }

    void operator|=(const NumDomSet& o);
    void operator&=(const NumDomSet& o);

    void exec(const Bin::Op op, const NumDomSet& o);
    
    void operator+=(const NumDomSet& o) { exec(Bin::Op::ADD, o); }
    void operator-=(const NumDomSet& o) { exec(Bin::Op::SUB, o); }

    bool operator==(const NumDomSet& b) const {
        return top == b.top && elems == b.elems;
    }

    void assume(Condition::Op op, const This& right);

    friend class OffsetDomSet;

    friend std::ostream& operator<<(std::ostream& os, const NumDomSet& a) {
        if (a.top) return os << "T";
        os << "{";
        for (auto e : a.elems)
            os << e << ",";
        os << "}";
        return os;
    }
};

class OffsetDomSet {
    using This = OffsetDomSet;
    // Naive set implementation
    bool top{};
    std::vector<uint64_t> elems;
public:
    template <typename ...Args>
    OffsetDomSet(Args... elems) : elems{static_cast<uint64_t>(elems)...} { }

    OffsetDomSet(const Top& _) : top{true} { }

    void operator|=(const OffsetDomSet& o);
    void operator&=(const OffsetDomSet& o);

    void exec(bool add, const NumDomSet& o);
    NumDomSet operator-(const OffsetDomSet& o) const;

    bool is_bot() const { return elems.empty(); }
    void to_bot() { elems.clear(); top = false; }
    void havoc() { elems.clear(); top = true; }

    void operator+=(const NumDomSet& o) { exec(true, o); }
    void operator-=(const NumDomSet& o) { exec(false, o); }

    friend OffsetDomSet operator+(const OffsetDomSet& a, const NumDomSet& b) { OffsetDomSet res = a; res += b; return res; }
    friend OffsetDomSet operator+(const NumDomSet& a, const OffsetDomSet& b) { return b + a; }

    void assume(Condition::Op op, const This& right);

    bool operator==(const OffsetDomSet& b) const { return top == b.top && elems == b.elems; }

    friend std::ostream& operator<<(std::ostream& os, const OffsetDomSet& a) {
        if (a.top) return os << "T";
        os << "{";
        for (auto e : a.elems)
            os << e << ",";
        os << "}";
        return os;
    }
};

template <typename T>
static T operator&(const T& a, const T& b) { T res = a; res &= b; return res; }

template <typename T>
static T operator|(const T& a, const T& b) { T res = a; res |= b; return res; }

template <typename T>
static T operator+(const T& a, const T& b) { T res = a; res += b; return res; }

template <typename T1, typename T2>
static T1 operator-(const T1& a, const T2& b) { T1 res = a; res -= b; return res; }
