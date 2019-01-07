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
        bool operator==(const Cell& o) const { return offset == o.offset && dom == o.dom && width == o.width; }
        bool operator<(const Cell& o) const { return offset < o.offset; } // TODO: reverse order // TODO: make overlapping equivalent
    };
    bool bot = true;
    std::set<Cell> cells;

    MemDom() { }
    MemDom(const Top& _) { havoc(); }
    
    RCP_domain numtop() const {
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
                pieces.push_back(Cell{.offset = cell.offset, .width = new_cell.offset - cell.offset, .dom = content });
            }
            if (cell.end() > new_cell.end()) {
                pieces.push_back(Cell{.offset = new_cell.end(), .width = cell.end() - new_cell.end(), .dom = content });
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
            auto& cell_a = *it_a;
            auto& cell_b = *it_b;
            if (cell_a.end() <= cell_b.offset) { merged.insert(cell_a); ++it_a; continue; }
            if (cell_b.end() <= cell_a.offset) { merged.insert(cell_b); ++it_b; continue; }

            if (cell_a.offset == cell_b.offset) {
                // TODO
                continue;
            }
            auto& lower  = cell_a.offset < cell_b.offset ? cell_a : cell_b;
            auto& higher = cell_a.offset < cell_b.offset ? cell_b : cell_a;

            uint64_t left_start = lower.offset;
            uint64_t left_end = higher.offset;
            uint64_t left_width = left_end - left_start;
            if (left_width > 0) {
                Cell left_part{
                    .offset = left_start,
                    .width = left_width,
                    .dom = {}
                };
            }
            uint64_t mid_start = higher.offset;
            uint64_t mid_end = std::min(lower.end(), higher.end());
            uint64_t mid_width = mid_end - mid_start;
            if (mid_width > 0) {
                Cell middle_part{
                    .offset = mid_start,
                    .width = mid_width,
                    .dom = {}
                };
            }
            uint64_t right_start = mid_end;
            uint64_t right_end = std::max(higher.end(), lower.end());
            uint64_t right_width = right_end - mid_end;
            if (right_width > 0) {
                Cell right_part{
                    .offset = right_start,
                    .width = right_width,
                    .dom = {}
                };
            }
        }
        merged.insert(it_b, b.cells.end());
        merged.insert(it_a, a.cells.end());
    }

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
