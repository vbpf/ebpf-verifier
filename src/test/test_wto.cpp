// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <catch2/catch_all.hpp>
#include "crab/cfg.hpp"
#include "crab/wto.hpp"

TEST_CASE("wto figure 1", "[wto]") {
    cfg_t cfg;

    // Construct the example graph in figure 1 of Bourdoncle,
    // "Efficient chaotic iteration strategies with widenings", 1993.

    // Add nodes.
    for (int i = 1; i <= 8; i++) {
        cfg.insert(label_t(i));
    }

    // Add edges.
    cfg.get_node(label_t::entry) >> cfg.get_node(label_t(1));
    cfg.get_node(label_t(1)) >> cfg.get_node(label_t(2));
    cfg.get_node(label_t(2)) >> cfg.get_node(label_t(3));
    cfg.get_node(label_t(3)) >> cfg.get_node(label_t(4));
    cfg.get_node(label_t(4)) >> cfg.get_node(label_t(5));
    cfg.get_node(label_t(4)) >> cfg.get_node(label_t(7));
    cfg.get_node(label_t(5)) >> cfg.get_node(label_t(6));
    cfg.get_node(label_t(6)) >> cfg.get_node(label_t(5));
    cfg.get_node(label_t(6)) >> cfg.get_node(label_t(7));
    cfg.get_node(label_t(7)) >> cfg.get_node(label_t(3));
    cfg.get_node(label_t(7)) >> cfg.get_node(label_t(8));
    cfg.get_node(label_t(8)) >> cfg.get_node(label_t::exit);

    wto_t wto(cfg);

    std::ostringstream os;
    os << wto;
    REQUIRE(os.str() == "entry 1 2 ( 3 4 ( 5 6 ) 7 ) 8 exit \n");
}

TEST_CASE("wto figure 2a", "[wto]") {
    cfg_t cfg;

    // Construct the example graph in figure 2a of Bourdoncle,
    // "Efficient chaotic iteration strategies with widenings", 1993.

    // Add nodes.
    for (int i = 1; i <= 5; i++) {
        cfg.insert(label_t(i));
    }

    // Add edges.
    cfg.get_node(label_t::entry) >> cfg.get_node(label_t(1));
    cfg.get_node(label_t(1)) >> cfg.get_node(label_t(2));
    cfg.get_node(label_t(1)) >> cfg.get_node(label_t(4));
    cfg.get_node(label_t(2)) >> cfg.get_node(label_t(3));
    cfg.get_node(label_t(3)) >> cfg.get_node(label_t::exit);
    cfg.get_node(label_t(4)) >> cfg.get_node(label_t(3));
    cfg.get_node(label_t(4)) >> cfg.get_node(label_t(5));
    cfg.get_node(label_t(5)) >> cfg.get_node(label_t(4));

    wto_t wto(cfg);

    std::ostringstream os;
    os << wto;
    REQUIRE(os.str() == "entry 1 ( 4 5 ) 2 3 exit \n");
}

TEST_CASE("wto figure 2b", "[wto]") {
    cfg_t cfg;

    // Construct the example graph in figure 2b of Bourdoncle,
    // "Efficient chaotic iteration strategies with widenings", 1993.

    // Add nodes.
    for (int i = 1; i <= 4; i++) {
        cfg.insert(label_t(i));
    }

    // Add edges.
    cfg.get_node(label_t::entry) >> cfg.get_node(label_t(1));
    cfg.get_node(label_t(1)) >> cfg.get_node(label_t(2));
    cfg.get_node(label_t(1)) >> cfg.get_node(label_t(4));
    cfg.get_node(label_t(2)) >> cfg.get_node(label_t(3));
    cfg.get_node(label_t(3)) >> cfg.get_node(label_t(1));
    cfg.get_node(label_t(3)) >> cfg.get_node(label_t::exit);
    cfg.get_node(label_t(4)) >> cfg.get_node(label_t(3));

    wto_t wto(cfg);

    std::ostringstream os;
    os << wto;
    REQUIRE(os.str() == "entry ( 1 4 2 3 ) exit \n");
}
