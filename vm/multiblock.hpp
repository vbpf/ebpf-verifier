#pragma once

#include <vector>
#include <string>
#include <algorithm>
#include <tuple>

#include <boost/optional.hpp>

#include "common.hpp"
#include "constraints.hpp"
#include "cfg.hpp"

using std::vector;
using std::string;
using std::tuple;

class multiblock_t
{
    cfg_t& cfg;
    basic_block_label_t current;
    basic_block_label_t exit;
    bool connected = false;
    basic_block_t& last()
    {
        return cfg.get_node(exit);
    }
public:

    multiblock_t(cfg_t& cfg, basic_block_label_t enter, basic_block_label_t exit) 
    : cfg(cfg), current(enter), exit(exit) { }

    multiblock_t(multiblock_t&& other)
    : cfg(other.cfg), current(other.current), exit(other.exit) { other.connected = true; }
    
    multiblock_t(const multiblock_t& other) = delete;
    
    ~multiblock_t()
    {
        if (!connected) {
            block() >> cfg.get_node(exit);
        }
    }

    basic_block_t& block()
    {
        return cfg.get_node(current);
    }

    void assertion(lin_cst_t cst) {
        block().assertion(cst, {current, (unsigned int)first_num(current), 0});
    }

    void assume(lin_cst_t cst) {
        block().assume(cst);
    }

    void assign(var_t lhs, var_t rhs) {
        block().assign(lhs, rhs);
    }

    void assign(var_t lhs, int rhs) {
        block().assign(lhs, rhs);
    }

    void havoc(var_t lhs) {
        block().havoc(lhs);
    }

    multiblock_t branch(basic_block_label_t suffix)
    {
        connected = true;
        basic_block_label_t e = current + ":" + suffix;
        basic_block_label_t x = current + ":" + suffix + ".exit";
        block() >> cfg.insert(e);
        cfg.insert(x) >> cfg.get_node(exit);
        return {cfg, e, x};
    }

    std::tuple<multiblock_t, multiblock_t> split(string suffix1, string suffix2) {
        multiblock_t b1{cfg, cfg.insert(current + ":" + suffix1).label(), cfg.insert(current + ":" + suffix1 + ".exit").label()};
        multiblock_t b2{cfg, cfg.insert(current + ":" + suffix2).label(), cfg.insert(current + ":" + suffix2 + ".exit").label()};
        block() >> b1.block();
        block() >> b2.block();
        current = current + ":ctd."; // TODO: make sure it's unique
        cfg.insert(current);
        b1.last() >> block();
        b2.last() >> block();
        return {std::move(b1), std::move(b2)};
    }
};
