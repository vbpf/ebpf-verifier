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
    bool is_top() const { return fds.all(); }

    void operator|=(const FdSetDom& o) { fds |= o.fds; }
    void operator&=(const FdSetDom& o) { fds &= o.fds; }

    bool operator==(const FdSetDom& o) const { return fds == o.fds; };

    friend std::ostream& operator<<(std::ostream& os, const FdSetDom& a) {
        return os << a.fds;
    }

    void assume(Condition::Op op, const This& b) { 
        if (op == Condition::Op::EQ) {
            (*this) &= b;
        } else if (op == Condition::Op::NE) {
            (*this) &= FdSetDom{fds.flip()};
        }
    }

    bool satisfied(Condition::Op op, const This& right) const {
        // inexact
        auto d = *this;
        d.assume(op, right);
        return d == *this;
    }
};

class NumDomSet {
    using This = NumDomSet;
    // Naive set implementation
    bool top{};
    std::vector<uint64_t> elems;

    static This make_top() { This res; res.havoc(); return res; }
    static This from_elems(std::vector<uint64_t>&& elems);
public:
    template <typename ...Args>
    NumDomSet(Args... elems) : elems{static_cast<uint64_t>(elems)...} { }

    NumDomSet(const Top& _) { havoc(); }

    bool is_bot() const { return !top && elems.empty(); }
    void to_bot() { elems.clear(); top = false; }
    void havoc() { elems.clear(); top = true; }
    bool is_top() const { return top; }

    void operator|=(const This& o);
    void operator&=(const This& o);

    void exec(const Bin::Op op, const NumDomSet& o);
    
    void operator+=(const This& o) { exec(Bin::Op::ADD, o); }
    void operator-=(const This& o) { exec(Bin::Op::SUB, o); }

    bool operator==(const This& b) const {
        return top == b.top && elems == b.elems;
    }

    void assume(Condition::Op op, const NumDomSet& right);
    bool satisfied(Condition::Op op, const NumDomSet& right) const {
        // inexact
        auto d = *this;
        d.assume(op, right);
        return d == *this;
    }

    friend class OffsetDomSet;

    friend std::ostream& operator<<(std::ostream& os, const This& a) {
        if (a.top) return os << "T";
        os << "{";
        for (auto e : a.elems)
            os << (int64_t)e << ",";
        os << "}";
        return os;
    }
};

class OffsetDomSet {
    using This = OffsetDomSet;
    // Naive set implementation
    bool top{};
    std::vector<int64_t> elems;
public:
    template <typename ...Args>
    OffsetDomSet(Args... elems) : elems{static_cast<int64_t>(elems)...} { }

    OffsetDomSet(const Top& _) { havoc(); }

    void operator|=(const This& o);
    void operator&=(const This& o);

    void exec(bool add, const NumDomSet& o);
    NumDomSet operator-(const This& o) const;

    bool is_bot() const { return !top && elems.empty(); }
    void to_bot() { elems.clear(); top = false; }
    void havoc() { elems.clear(); top = true; }
    bool is_top() const { return top; }

    void operator+=(const NumDomSet& o) { exec(true, o); }
    void operator-=(const NumDomSet& o) { exec(false, o); }

    friend This operator+(const This& a, const NumDomSet& b) { This res = a; res += b; return res; }
    friend This operator+(const NumDomSet& a, const This& b) { return b + a; }

    void assume(Condition::Op op, const OffsetDomSet& right);
    bool satisfied(Condition::Op op, const OffsetDomSet& right) const {
        // inexact
        auto d = *this;
        d.assume(op, right);
        return d == *this;
    }

    bool operator==(const This& b) const { return top == b.top && elems == b.elems; }

    friend std::ostream& operator<<(std::ostream& os, const This& a) {
        if (a.top) return os << "T";
        os << "{";
        for (auto e : a.elems)
            os << e << ",";
        os << "}";
        return os;
    }
};

template <typename T>
inline T operator&(const T& a, const T& b) { T res = a; res &= b; return res; }

template <typename T>
inline T operator|(const T& a, const T& b) { T res = a; res |= b; return res; }

template <typename T>
inline T operator+(const T& a, const T& b) { T res = a; res += b; return res; }

template <typename T1, typename T2>
inline T1 operator-(const T1& a, const T2& b) { T1 res = a; res -= b; return res; }
