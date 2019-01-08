#pragma once

#include <set>
#include <vector>
#include <limits>

#include "ai_dom_rcp.hpp"

using std::min;
using std::max;
using std::minmax;

struct MemDom {
    struct Cell {
        int64_t offset;
        int64_t width{};
        RCP_domain dom;
        // end is 1 after the last
        int64_t end() const { return offset + width; }
        bool overlapping(int64_t other_offset, int64_t other_width) const {
            return (offset <= other_offset && offset + width > other_offset)
                || (other_offset <= offset && other_offset + other_width > offset);
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
            auto [lower_start, higher_start] = minmax(a, b, [](auto& a, auto& b) {
                                                                    return a.offset < a.offset; });
            auto [lower_end, higher_end] = minmax(a, b, [](auto& a, auto& b) {
                                                              return a.end() < b.end(); });
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
        bool operator<(const Cell& o) const { return offset < o.offset; } // TODO: reverse order // TODO: make overlapping equivalent
    };
    bool bot = true;
    std::vector<Cell> cells;

    MemDom() { }
    MemDom(const Top& _) { havoc(); }
    
    static RCP_domain numtop() {
        return RCP_domain{}.with_num(TOP);
    }

    RCP_domain load(const OffsetDomSet& offset_dom, uint64_t _width) const {
        int64_t width = static_cast<int64_t>(_width);
        if (!offset_dom.is_single()) {
            return {TOP};
        }
        int64_t offset = offset_dom.elems.front();

        int64_t min_offset = 0xFFFFFF;
        int64_t total_width = 0;
        int64_t max_end = 0;
        bool all_must_be_num = true;
        for (const Cell& cell : cells) {
            if (!cell.overlapping(offset, width)) continue;

            if (cell.offset == offset && cell.width == width) {
                return cell.dom;
            }
            min_offset = min(cell.offset, min_offset);
            total_width += cell.width;
            max_end = max(cell.end(), max_end);
            if (!cell.dom.must_be_num())
                all_must_be_num = false;
        }
        if (total_width == 0) return {TOP};
        if (min_offset > offset || max_end < offset + width) return {TOP};
        if (!all_must_be_num) return {TOP};
        if (min_offset + total_width < max_end) return {TOP};
        return numtop();
    }

    void store_dynamic(const OffsetDomSet& offset_dom, const NumDomSet& _width, const RCP_domain& value) {
        if (_width.is_bot() || offset_dom.is_bot()) return;
        if (_width.is_single() && offset_dom.is_single()) {
            store(offset_dom, _width.elems.front(), value);
            return;
        }
        RCP_domain content = value.must_be_num() ? numtop() : RCP_domain(TOP);
        int64_t min_offset = offset_dom.is_top() ? 0          : *std::min_element(offset_dom.elems.begin(), offset_dom.elems.end());
        int64_t max_offset = offset_dom.is_top() ? STACK_SIZE : *std::max_element(offset_dom.elems.begin(), offset_dom.elems.end());
        uint64_t min_width = _width.is_top() ? 0                       : *std::min_element(_width.elems.begin(), _width.elems.end());
        uint64_t max_width = _width.is_top() ? STACK_SIZE - min_offset : *std::max_element(_width.elems.begin(), _width.elems.end());
        if (min_width > 0 && max_offset < STACK_SIZE)
            store({max_offset}, min_width, content);
        MemDom tmp = *this;
        tmp.store({min_offset}, max_width, content);
        (*this) |= tmp;
    }

    void store(const OffsetDomSet& offset_dom, uint64_t _width, const RCP_domain& value) {
        int64_t width = static_cast<int64_t>(_width);
        bot = false;
        if (!offset_dom.is_single()) {
            havoc();
            return;
        }
        Cell new_cell{ .offset = offset_dom.elems.front(), .width = width, .dom = value };
        std::vector<Cell> to_remove;
        std::vector<Cell> pieces;
        for (const Cell& cell : cells) {
            if (cell.end() <= new_cell.offset) continue;
            if (cell.offset >= new_cell.end()) continue;

            to_remove.push_back(cell);

            RCP_domain content = cell.dom.must_be_num() ? numtop() : RCP_domain(TOP);
            // If content is TOP, we can remove, unless we want to track initialization
            if (cell.offset < new_cell.offset) {
                pieces.push_back(Cell::from_range(cell.offset, new_cell.offset, content));
            }
            if (cell.end() > new_cell.end()) {
                pieces.push_back(Cell::from_range(new_cell.end(), cell.end(), content));
            }
        }
        assert(pieces.size() <= 2);
        for (auto p : to_remove) cells.erase(std::remove(cells.begin(), cells.end(), p), cells.end());
        for (auto p : pieces) cells.push_back(p);
        cells.push_back(new_cell);
        std::sort(cells.begin(), cells.end());
    }

    void operator|=(const MemDom& b) {
        if (this == &b) return;
        if (bot) { *this = b; return; }
        if (b.bot) return;
        if (is_top()) { return; }
        if (b.is_top()) { havoc(); return; }
        
        std::copy(b.cells.begin(), b.cells.end(), std::back_inserter(cells));
        std::sort(cells.begin(), cells.end());
        // There's at least one cell
        std::vector<Cell> new_cells;
        int to_remove = 0;
        for (auto it = cells.begin(); std::next(it) < cells.end(); ++it) {
            Cell& current = *it;
            Cell& after = *std::next(it);

            if (current.end() <= after.offset) {
                continue;
            }

            if (current.offset == after.offset && current.width == after.width) {
                after.dom |= current.dom;
                current.offset = std::numeric_limits<int64_t>().max();
                current.width = 0;
                to_remove++;
                continue;
            }

            auto [left, mid1, mid2, right] = Cell::split(current, after);
            mid1.dom |= mid2.dom;

            current = mid1;
            
            if (left.width > 0) new_cells.push_back(left);

            if (right.width == 0) {
                right.offset = std::numeric_limits<int64_t>().max();
                to_remove++;
                continue;
            }

            // right should stay for next iteration
            // TODO: add test for this
            after = right;
        }
        std::move(new_cells.begin(), new_cells.end(), std::back_inserter(cells));
        std::sort(cells.begin(), cells.end());
        cells.resize(cells.size() - to_remove);
    }

    void operator&=(const MemDom& o) {
        if (this == &o) return;
        if (is_bot() || o.is_bot()) { to_bot(); return; }
        if (is_top()) { *this = o; return; }
    }

    bool is_bot() const { return bot; }
    bool is_top() const { return !bot && cells.empty(); }

    void havoc() { cells.clear(); bot = false; }
    void to_bot() { cells.clear(); bot = true; }

    bool operator==(const MemDom& o) const { return bot == o.bot && cells == o.cells; }

    friend std::ostream& operator<<(std::ostream& os, const MemDom& d) {
        if (d.bot) return os << "{BOT}";
        os << "{";
        for (auto cell : d.cells) {
            os << cell.offset << ":" << (int64_t)cell.width << "->" << cell.dom << ", ";
        }
        os << "}";
        return os;
    }
};
