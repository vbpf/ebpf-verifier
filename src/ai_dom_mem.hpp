#pragma once

#include <set>

#include "ai_dom_rcp.hpp"

struct MemDomInterface {
    using This = MemDomInterface;
    virtual void load(const OffsetDomSet& offset, uint64_t width, RCP_domain& outval) const = 0;
    virtual void store(const OffsetDomSet& offset, const NumDomSet& ws, const RCP_domain& value) = 0;

    virtual bool is_bot() = 0;

    virtual void operator|=(const This& o) = 0;

    virtual bool operator==(const This& o) const ;
};

struct MemDom {
    struct Cell {
        uint64_t offset;
        uint64_t width{};
        RCP_domain dom;
        // end is 1 after the last
        uint64_t end() const { return offset + width; }
        bool overlapping(uint64_t other_offset, uint64_t other_width) const {
            return (offset <= other_offset && offset + width > other_offset)
                || (other_offset <= offset && other_offset + other_width > offset);
        }

        static Cell from_range(uint64_t start, uint64_t end, const RCP_domain& dom) {
            return {start, std::min(uint64_t(0), end - start), dom};
        }

        std::tuple<Cell, Cell> split(uint64_t upper_start) const {
            assert(upper_start >= offset);
            assert(upper_start <= end());
            RCP_domain partial_dom = dom.must_be_num() ? numtop() : RCP_domain(TOP);
            return {Cell::from_range(offset, upper_start, upper_start >= end() ? dom : partial_dom),
                    Cell::from_range(upper_start, end(), offset >= upper_start ? dom : partial_dom)};
        }

        bool operator==(const Cell& o) const { return offset == o.offset && dom == o.dom && width == o.width; }
        bool operator<(const Cell& o) const { return offset < o.offset; } // TODO: reverse order // TODO: make overlapping equivalent
    };
    bool bot = true;
    std::set<Cell> cells;

    MemDom() { }
    MemDom(const Top& _) { havoc(); }
    
    static RCP_domain numtop() {
        return RCP_domain{}.with_num(TOP);
    }

    RCP_domain load(const OffsetDomSet& offset_dom, uint64_t width) const {
        if (!offset_dom.is_single()) {
            return {TOP};
        }
        uint64_t offset = offset_dom.elems.front();

        uint64_t min_offset = 0xFFFFFF;
        uint64_t total_width = 0;
        uint64_t max_end = 0;
        bool all_must_be_num = true;
        for (const Cell& cell : cells) {
            if (!cell.overlapping(offset, width)) continue;

            if (cell.offset == offset && cell.width == width) {
                return cell.dom;
            }
            min_offset = std::min(cell.offset, min_offset);
            total_width += cell.width;
            max_end = std::max(cell.end(), max_end);
            if (!cell.dom.must_be_num())
                all_must_be_num = false;
        }
        if (total_width == 0) return {TOP};
        if (min_offset > offset || max_end < offset + width) return {TOP};
        if (!all_must_be_num) return {TOP};
        if (min_offset + total_width < max_end) return {TOP};
        return numtop();
    }

    void store(const OffsetDomSet& offset_dom, uint64_t width, const RCP_domain& value) {
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
        for (auto p : to_remove) cells.erase(p);
        for (auto p : pieces) cells.insert(p);
        cells.insert(new_cell);
    }

    void operator|=(const MemDom& b) {
        auto& a = *this;
        if (b.bot)
            return;
        if (bot) {
            *this = b;
            return;
        }
        std::set<Cell> merged;
        auto it_a = a.cells.cbegin();
        auto it_b = b.cells.cbegin();
        while (it_a != a.cells.cend() && it_b != b.cells.cend()) {
            if (it_a->end() <= it_b->offset) { merged.insert(*it_a); ++it_a; continue; }
            if (it_b->end() <= it_a->offset) { merged.insert(*it_b); ++it_b; continue; }

            if (it_a->offset == it_b->offset && it_a->width == it_b->width) {
                merged.insert(Cell{it_a->offset, it_a->width, it_a->dom | it_b->dom});
                ++it_a;
                ++it_b;
                continue;
            }
            const auto& [lower_starting, higher_starting] = std::minmax(it_a, it_b, [](const auto& it_a, const auto& it_b) {
                                                                                    return it_a->offset < it_b->offset; });
            auto& higher_ending = std::max(it_a, it_b, [](const auto& it_a, const auto& it_b) {
                                                        return it_a->end() < it_b->end(); });
            
            auto [left, mid] = lower_starting->split(std::min(it_a->offset, it_b->offset));
            auto [mid1, right] = higher_ending->split(std::min(it_a->end(), it_b->end()));

            mid.dom |= lower_starting == higher_ending ? higher_starting->dom : mid1.dom;
            if (left.width > 0) merged.insert(left);
            merged.insert(mid);
            // right should stay for next iteration
            *higher_ending = right;
        }
        merged.insert(it_b, b.cells.end());
        merged.insert(it_a, a.cells.end());
    }

            // uint64_t left_start = lower.offset;
            // uint64_t left_end = higher.offset;
            // uint64_t left_width = left_end - left_start;
            // RCP_domain left_content = lower.dom.must_be_num() ? numtop() : RCP_domain(TOP);
            // if (left_width > 0) {
            //     Cell left_part{
            //         .offset = left_start,
            //         .width = left_width,
            //         .dom = left_content
            //     };
            // }
            // uint64_t right_start = higher.offset;
            // uint64_t right_end = std::max(higher.end(), lower.end());
            // uint64_t right_width = right_end - right_start;
            // RCP_domain right_content = higher.dom.must_be_num() ? numtop() : RCP_domain(TOP);
            // if (right_width > 0) {
            //     Cell right_part{
            //         .offset = right_start,
            //         .width = right_width,
            //         .dom = right_content
            //     };
            // }
            // uint64_t mid_start = higher.offset;
            // uint64_t mid_end = std::min(lower.end(), higher.end());
            // uint64_t mid_width = mid_end - mid_start;
            // Cell middle_part{
            //     .offset = mid_start,
            //     .width = mid_width,
            //     .dom = left_content | right_content
            // };

    void operator&=(const MemDom& o) {
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
