#pragma once

#include <set>
#include <vector>

#include "ai_dom_rcp.hpp"

using std::max;
using std::min;
using std::minmax;

struct MemDom {
    struct Cell {
        int64_t offset;
        int64_t width{};
        RCP_domain dom;
        // end is 1 after the last
        int64_t end() const { return offset + width; }
        bool overlapping(int64_t other_offset, int64_t other_width) const {
            return (offset <= other_offset && offset + width > other_offset) ||
                   (other_offset <= offset && other_offset + other_width > offset);
        }

        static Cell from_range(int64_t start, int64_t end, const RCP_domain& dom) {
            return {start, max(int64_t(0), end - start), dom};
        }

        std::tuple<Cell, Cell> split(int64_t upper_start) const {
            assert(upper_start >= offset);
            assert(upper_start <= end());
            RCP_domain partial_dom = dom.must_be_num() ? numtop() : RCP_domain(TOP);
            Cell lower = Cell::from_range(offset, upper_start, upper_start >= end() ? dom : partial_dom);
            Cell upper = Cell::from_range(upper_start, end(), offset >= upper_start ? dom : partial_dom);
            assert(lower.width + upper.width == width);
            return {lower, upper};
        }

        static std::tuple<Cell, Cell, Cell, Cell> split(const Cell& a, const Cell& b) {
            auto [lower_start, higher_start] = minmax(a, b, [](auto& a, auto& b) { return a.offset < a.offset; });
            auto [lower_end, higher_end] = minmax(a, b, [](auto& a, auto& b) { return a.end() < b.end(); });
            auto [left, mid1] = lower_start.split(higher_start.offset);
            if (&lower_start == &higher_end) {
                assert(higher_start.end() >= mid1.offset);
                auto [mid2, right] = mid1.split(higher_start.end());
                return {left, mid2, higher_start, right};
            } else {
                assert(lower_end.end() >= higher_end.offset);
                auto [mid2, right] = higher_end.split(lower_end.end());
                return {left, mid1, mid2, right};
            }
        }

        bool operator==(const Cell& o) const { return offset == o.offset && dom == o.dom && width == o.width; }
        bool operator<(const Cell& o) const {
            return offset < o.offset;
        } // TODO: reverse order // TODO: make overlapping equivalent
    };
    bool bot = true;
    std::vector<Cell> cells;

    MemDom() {}
    MemDom(const Top& _) { havoc(); }

    static RCP_domain numtop() { return RCP_domain{}.with_num(TOP); }

    RCP_domain load(const OffsetDomSet& offset_dom, uint64_t _width) const;

    void store_dynamic(const OffsetDomSet& offset_dom, const NumDomSet& _width, const RCP_domain& value);

    void store(const OffsetDomSet& offset_dom, uint64_t _width, const RCP_domain& value);

    void operator|=(const MemDom& b);

    void operator&=(const MemDom& o) {
        if (this == &o)
            return;
        if (is_bot() || o.is_bot()) {
            to_bot();
            return;
        }
        if (is_top()) {
            *this = o;
            return;
        }
    }

    bool is_bot() const { return bot; }
    bool is_top() const { return !bot && cells.empty(); }

    void havoc() {
        cells.clear();
        bot = false;
    }
    void to_bot() {
        cells.clear();
        bot = true;
    }

    bool operator==(const MemDom& o) const { return bot == o.bot && cells == o.cells; }

    friend std::ostream& operator<<(std::ostream& os, const MemDom& d) {
        if (d.bot)
            return os << "{BOT}";
        os << "{";
        for (auto cell : d.cells) {
            os << cell.offset << ":" << (int64_t)cell.width << "->" << cell.dom << ", ";
        }
        os << "}";
        return os;
    }
};
