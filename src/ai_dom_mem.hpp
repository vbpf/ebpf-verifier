#pragma once

#include <map>

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
    struct Item {
        uint64_t offset;
        uint64_t width{};
        RCP_domain dom;
        // end is 1 after the last
        uint64_t end() const { return offset + width; }
        bool overlapping(uint64_t other_offset, uint64_t other_width) const {
            return (offset <= other_offset && offset + width > other_offset)
                || (other_offset <= offset && other_offset + other_width > offset);
        }
        bool operator==(const Item& o) const { return offset == o.offset && dom == o.dom && width == o.width; }
        bool operator<(const Item& o) const { return offset < o.offset; } // TODO: reverse order // TODO: make overlapping equivalent
    };
    bool bot = true;
    std::vector<Item> items;

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
        for (int i = items.size()-1; i>=0; --i) {
            auto item = items[i];
            if (!item.overlapping(offset, width)) continue;

            if (item.offset == offset && item.width == width) {
                return item.dom;
            }
            min_offset = std::min(item.offset, min_offset);
            total_width += item.width;
            max_end = std::max(item.end(), max_end);
            if (!item.dom.must_be_num())
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
        uint64_t offset = offset_dom.elems.front();
        Item new_item{
            .offset = offset,
            .width = width,
            .dom = value
        };
        for (int i = 0; i < items.size(); ++i) {
            auto& item = items[i];
            if (item.offset == offset) {
                if (item.width == width) {
                    item = new_item;
                    return;
                } else if (item.width < width) {
                    item = new_item;
                    // deal with next items, might be overridden
                    return;
                } else {
                    item.width -= width;
                    item.offset += width;
                }
            } else if (item.offset >= new_item.end()) {
                // not found
                break;
            } else if (item.offset > offset) {
                // __--
                item = Item{
                    .offset = new_item.end(),
                    .width = item.offset - new_item.end(),
                    .dom = TOP
                };
                if (item.dom.must_be_num())
                    item.dom = numtop();
                break;
            } else if (item.end() > new_item.end()) {
                // -__-
                RCP_domain content{TOP};
                if (item.dom.must_be_num())
                    item.dom = numtop();
                item = Item{
                    .offset = item.offset,
                    .width = item.offset - new_item.end(),
                    .dom = content
                };
                items.push_back(Item{
                    .offset = new_item.end(),
                    .width = item.end() - new_item.end(),
                    .dom = content
                });
            } else if (item.offset > new_item.end()) {
                // --__
                item = Item{
                    .offset = item.offset,
                    .width = item.offset - new_item.end(),
                    .dom = TOP
                };
                if (item.dom.must_be_num())
                    item.dom = numtop();
            }
        }
        items.push_back(new_item);
        std::sort(items.begin(), items.end());
    }

    void operator|=(const MemDom& o) {
        //std::cerr << *this << " | " << o;
        if (o.bot)
            return;
        if (bot) {
            *this = o;
        } else {
            return;
        }
        //std::cerr << " = " << *this << "\n";
    }

    void operator&=(const MemDom& o) {
        if (is_bot() || o.is_bot()) { to_bot(); return; }
        if (is_top()) { *this = o; return; }
    }

    bool is_bot() const { return bot; }
    bool is_top() const { return !bot && items.empty(); }

    void havoc() { items.clear(); bot = false; }
    void to_bot() { items.clear(); bot = true; }

    bool operator==(const MemDom& o) const { return bot == o.bot && items == o.items; }

    friend std::ostream& operator<<(std::ostream& os, const MemDom& d) {
        if (d.bot) return os << "{BOT}";
        os << "{";
        for (auto item : d.items) {
            os << item.offset << ":" << (int64_t)item.width << "->" << item.dom << ", ";
        }
        os << "}";
        return os;
    }
};
