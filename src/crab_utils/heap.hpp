#pragma once
/*********************************************************************************[Heap.h]
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
******************************************************************************************/
#include <vector>

//=========================================================================================
// A heap implementation with support for decrease/increase key.
//=========================================================================================

namespace crab {

template <class Comp>
class Heap {
    Comp lt;
    std::vector<int> heap;    // heap of ints
    std::vector<int> indices; // int -> index in heap

    // Index "traversal" functions
    static inline int left(int i) { return i * 2 + 1; }
    static inline int right(int i) { return (i + 1) * 2; }
    static inline int parent(int i) { return (i - 1) >> 1; }

    inline void percolateUp(int i) {
        int x = heap[i];
        while (i != 0 && lt(x, heap[parent(i)])) {
            heap[i] = heap[parent(i)];
            indices[heap[i]] = i;
            i = parent(i);
        }
        heap[i] = x;
        indices[x] = i;
    }

    inline void percolateDown(int i) {
        int x = heap[i];
        while (static_cast<size_t>(left(i)) < heap.size()) {
            int child = static_cast<size_t>(right(i)) < heap.size() && lt(heap[right(i)], heap[left(i)]) ? right(i) : left(i);
            if (!lt(heap[child], x))
                break;
            heap[i] = heap[child];
            indices[heap[i]] = i;
            i = child;
        }
        heap[i] = x;
        indices[x] = i;
    }

    [[nodiscard]] bool heapProperty(int i) const {
        return i >= heap.size() ||
               ((i == 0 || !lt(heap[i], heap[parent(i)])) && heapProperty(left(i)) && heapProperty(right(i)));
    }

  public:
    explicit Heap(const Comp& c) : lt(c) {}

    [[nodiscard]] int size() const { return heap.size(); }
    [[nodiscard]] bool empty() const { return heap.empty(); }
    [[nodiscard]] bool inHeap(int n) const { return static_cast<size_t>(n) < indices.size() && indices[n] >= 0; }
    int operator[](int index) const {
        assert(static_cast<size_t>(index) < heap.size());
        return heap[index];
    }

    void decrease(int n) {
        assert(inHeap(n));
        percolateUp(indices[n]);
    }

    void insert(int n) {
        assert(n >= 0);
        if (static_cast<size_t>(n) >= indices.size())
            indices.resize(n + 1, -1);
        assert(!inHeap(n));

        indices[n] = static_cast<int>(heap.size());
        heap.push_back(n);
        percolateUp(indices[n]);
    }

    int removeMin() {
        int x = heap[0];
        heap[0] = heap.back();
        indices[heap[0]] = 0;
        indices[x] = -1;
        heap.pop_back();
        if (heap.size() > 1)
            percolateDown(0);
        return x;
    }

    void clear() {
        for (int i : heap)
            indices[i] = -1;
#ifdef NDEBUG
        for (int i = 0; i < indices.size(); i++)
            assert(indices[i] == -1);
#endif
        heap.clear();
    }
};
} // namespace crab
