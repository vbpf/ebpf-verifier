#pragma once

/************************************************************************************[Vec.h]
MiniSat -- Copyright (c) 2003-2006, Niklas Een, Niklas Sorensson

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
********************************************************************************************/

#include <cassert>
#include <cstdlib>
#include <new>

//===========================================================================================
// Automatically resizable arrays
//
// NOTE! Don't use this vector on datatypes that cannot be re-located
//       in memory (with realloc)
//===========================================================================================

namespace crab {

template <class T>
class vec {
    T* data;
    int sz;
    int cap;

    void init(int size, const T& pad);
    void grow(int min_cap);

    // Don't allow copying (error prone):
    vec<T>& operator=(vec<T>& other) {
        assert(0);
        return *this;
    }
    /*         vec        (vec<T>& other) { assert(0); } */

    static inline int imin(int x, int y) {
        int mask = (x - y) >> (sizeof(int) * 8 - 1);
        return (x & mask) + (y & (~mask));
    }

    static inline int imax(int x, int y) {
        int mask = (y - x) >> (sizeof(int) * 8 - 1);
        return (x & mask) + (y & (~mask));
    }

  public:
    // Constructors:
    vec() : data(NULL), sz(0), cap(0) {}
    vec(int size) : data(NULL), sz(0), cap(0) { growTo(size); }
    vec(int size, const T& pad) : data(NULL), sz(0), cap(0) { growTo(size, pad); }
    ~vec() { clear(true); }

    // GKG: Added stuff - copy & move ctors, plus range interface.
    vec(const vec<T>& o) : data(NULL), sz(0), cap(0) {
        capacity(o.cap);
        for (int ii = 0; ii < o.sz; ii++)
            new (data + ii) T(o[ii]);
        sz = o.sz;
    }

    vec(vec<T>&& o) : data(o.data), sz(o.sz), cap(o.cap) {
        o.data = nullptr;
        o.sz = 0;
        o.cap = 0;
    }
    vec<T>& operator=(vec<T>&& o) {
        if (data)
            free(data);
        data = o.data;
        o.data = nullptr;
        sz = o.sz;
        o.sz = 0;
        cap = o.cap;
        o.cap = 0;
        return *this;
    }
    vec<T>& operator=(const vec<T>& o) {
        clear();
        capacity(o.cap);
        for (int ii = 0; ii < o.sz; ii++)
            new (data + ii) T(o[ii]);
        sz = o.sz;
        return *this;
    }

    T* begin() const { return data; }
    T* end() const { return data + sz; }

    // Size operations:
    int size() const { return sz; }
    void shrink(int nelems) {
        assert(nelems <= sz);
        for (int i = 0; i < nelems; i++)
            sz--, data[sz].~T();
    }

    void pop() { sz--, data[sz].~T(); }
    void growTo(int size);
    void growTo(int size, const T& pad);
    void clear(bool dealloc = false);
    void capacity(int size) { grow(size); }

    // Stack interface:
    void push() {
        if (sz == cap) {
            cap = imax(2, (cap * 3 + 1) >> 1);
            data = (T*)realloc(static_cast<void*>(data), cap * sizeof(T));
        }
        new (&data[sz]) T();
        sz++;
    }

    void push(const T& elem) {
        if (sz == cap) {
            cap = imax(2, (cap * 3 + 1) >> 1);
            data = (T*)realloc(static_cast<void*>(data), cap * sizeof(T));
        }
        data[sz++] = elem;
    }

    const T& last() const { return data[sz - 1]; }
    T& last() { return data[sz - 1]; }

    // Vector interface:
    const T& operator[](int index) const { return data[index]; }
    T& operator[](int index) { return data[index]; }
};

template <class T>
void vec<T>::grow(int min_cap) {
    if (min_cap <= cap)
        return;
    if (cap == 0)
        cap = (min_cap >= 2) ? min_cap : 2;
    else
        do
            cap = (cap * 3 + 1) >> 1;
        while (cap < min_cap);
    data = (T*)realloc(static_cast<void*>(data), cap * sizeof(T));
}

template <class T>
void vec<T>::growTo(int size, const T& pad) {
    if (sz >= size)
        return;
    grow(size);
    for (int i = sz; i < size; i++)
        new (&data[i]) T(pad);
    sz = size;
}

template <class T>
void vec<T>::growTo(int size) {
    if (sz >= size)
        return;
    grow(size);
    for (int i = sz; i < size; i++)
        new (&data[i]) T();
    sz = size;
}

template <class T>
void vec<T>::clear(bool dealloc) {
    if (data != NULL) {
        for (int i = 0; i < sz; i++)
            data[i].~T();
        sz = 0;
        if (dealloc)
            free(data), data = NULL, cap = 0;
    }
}

} // end namespace crab
