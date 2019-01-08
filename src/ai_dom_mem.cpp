#include <set>
#include <vector>
#include <limits>

#include "ai_dom_rcp.hpp"
#include "ai_dom_mem.hpp"

using std::min;
using std::max;
using std::minmax;

RCP_domain MemDom::load(const OffsetDomSet& offset_dom, uint64_t _width) const {
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

void MemDom::store_dynamic(const OffsetDomSet& offset_dom, const NumDomSet& _width, const RCP_domain& value) {
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

void MemDom::store(const OffsetDomSet& offset_dom, uint64_t _width, const RCP_domain& value) {
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

void MemDom::operator|=(const MemDom& b) {
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
    auto remove = [&](Cell& c) {
        c.offset = std::numeric_limits<int64_t>().max();
        c.width = 0;
        to_remove++;
    };
    cells.emplace_back();
    remove(cells.back());
    for (auto it = cells.begin(); std::next(it) < cells.end(); ++it) {
        Cell& current = *it;
        Cell& after = *std::next(it);

        if (current.end() <= after.offset || current.width == 0) {
            remove(current);
            continue;
        }
        
        auto [_, mid1, mid2, right] = Cell::split(current, after);
        mid1.dom |= mid2.dom;

        current = mid1;

        // right should stay for next iteration
        after = right;
    }
    std::move(new_cells.begin(), new_cells.end(), std::back_inserter(cells));
    std::sort(cells.begin(), cells.end());
    cells.resize(cells.size() - to_remove);
}
