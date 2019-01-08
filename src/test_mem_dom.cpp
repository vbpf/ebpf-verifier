#include "catch.hpp"

#include <iostream>
#include <unordered_map>
#include <initializer_list>

#include "ai_dom_set.hpp"
#include "ai_dom_rcp.hpp"
#include "ai_dom_mem.hpp"

const RCP_domain T = RCP_domain{TOP};
const RCP_domain NT = RCP_domain{}.with_num(TOP);

using D = MemDom;
auto top = []() -> D { return D{TOP}; };
auto bot = []() -> D { return D{}; };

MemDom mem(std::initializer_list<MemDom::Cell> lst) {
    MemDom m;
    for (auto c : lst) 
        m.store(c.offset, c.width, c.dom);
    return m;
}

TEST_CASE( "mem_dom_join", "[dom][domain][mem]" ) {
    REQUIRE(D{} == bot());
    REQUIRE_FALSE(bot() == top());

    REQUIRE((top() & bot()) == bot());
    REQUIRE((bot() & top()) == bot());

    REQUIRE((top() | bot()) == top());
    REQUIRE((bot() | top()) == top());

    SECTION("WithTop") {
        D mem;
        const RCP_domain n = RCP_domain{}.with_num(5);
        mem.store({0}, 4, n);
        REQUIRE((mem | top()) == top());
    }
    SECTION("WithSelf") {
        D mem;
        const RCP_domain n = RCP_domain{}.with_num(5);
        mem.store({0}, 4, n);
        REQUIRE((mem | mem) == mem);
    }
    SECTION("Nonoverlap") {
        const RCP_domain n1 = RCP_domain{}.with_num(5);
        const RCP_domain n2 = RCP_domain{}.with_num(9);
        const RCP_domain n3 = RCP_domain{}.with_num(3);

        D::Cell c1{0, 4, n1};
        D::Cell c2{4, 4, n2};
        D::Cell c3{8, 4, n3};
        D mem1 = mem({c1});
        D mem2 = mem({c2});
        D mem3 = mem({c3});


        D expected12 = mem({c1, c2});
        REQUIRE((mem1 | mem2) == expected12);
        REQUIRE((mem2 | mem1) == expected12);

        D expected13 = mem({c1, c3});
        REQUIRE((mem1 | mem3) == expected13);
        REQUIRE((mem3 | mem1) == expected13);

        D expected23 = mem({c2, c3});
        REQUIRE((mem2 | mem3) == expected23);
        REQUIRE((mem3 | mem2) == expected23);
    }
}

TEST_CASE( "mem_dom_no_writes", "[dom][domain][mem]" ) {
    D mem;
    REQUIRE(mem.load({0}, 3) == T);
    REQUIRE(mem.load({0}, 1) == T);
    REQUIRE(mem.load({4}, 100) == T);
}

TEST_CASE( "mem_dom_single_write", "[dom][domain][mem]" ) {

    SECTION("AllTypes") {
        for (auto n : {
                        RCP_domain{}.with_num(5),
                        RCP_domain{}.with_fd(2),
                        RCP_domain{}.with_map(2, 5),
                        RCP_domain{}.with_packet(7),
                        RCP_domain{}.with_stack(17)
        }) {
            D mem;
            mem.store({0}, 4, n);
            REQUIRE(mem.load({0}, 4) == n);
        }
    }

    D mem;
    const RCP_domain n = RCP_domain{}.with_num(5);
    SECTION("WriteToStart") {
        mem.store({0}, 4, n);

        REQUIRE(mem.load({0}, 4) == n);

        REQUIRE(mem.load({0}, 3) == NT);
        REQUIRE(mem.load({1}, 3) == NT);

        REQUIRE(mem.load({0}, 5) == T);
        REQUIRE(mem.load({1}, 4) == T);
    }

    SECTION("WriteToMiddle") {
        mem.store({1}, 4, n);

        REQUIRE(mem.load({1}, 4) == n);

        REQUIRE(mem.load({1}, 3) == NT);
        REQUIRE(mem.load({2}, 3) == NT);

        REQUIRE(mem.load({1}, 5) == T);
        REQUIRE(mem.load({2}, 4) == T);
    }

    SECTION("WriteToEnd") {
        mem.store({STACK_SIZE-4}, 4, n);

        REQUIRE(mem.load({STACK_SIZE-4}, 4) == n);

        REQUIRE(mem.load({STACK_SIZE-4}, 3) == NT);
        REQUIRE(mem.load({STACK_SIZE-3}, 3) == NT);

        REQUIRE(mem.load({STACK_SIZE-4}, 5) == T);
        REQUIRE(mem.load({STACK_SIZE-3}, 4) == T);
    }
}

TEST_CASE( "mem_dom_two_writes", "[dom][domain][mem]" ) {
    const RCP_domain n1 = RCP_domain{}.with_num(5);
    const RCP_domain n2 = RCP_domain{}.with_num(9);
    const RCP_domain n3 = RCP_domain{}.with_num(3);

    SECTION("NonOverlapping") {
        D mem;
        mem.store({4}, 4, n1);
        mem.store({8}, 4, n2);

        D mem1;
        mem1.store({8}, 4, n2);
        mem1.store({4}, 4, n1);
        REQUIRE(mem == mem1);


        // D mem3; mem3.store({8}, 4, n2);
        // D mem4; mem4.store({4}, 4, n1);
        // REQUIRE(mem3 | mem4 == mem);

        REQUIRE(mem.load({4}, 4) == n1);
        REQUIRE(mem.load({8}, 4) == n2);

        REQUIRE(mem.load({0}, 4) == T);
        REQUIRE(mem.load({1}, 3) == T);
        REQUIRE(mem.load({2}, 2) == T);
        REQUIRE(mem.load({3}, 1) == T);
        REQUIRE(mem.load({12}, 4) == T);

        REQUIRE(mem.load({6}, 4) == NT);
        REQUIRE(mem.load({4}, 8) == NT);

        REQUIRE(mem.load({0}, 5) == T);
        REQUIRE(mem.load({0}, 9) == T);
        REQUIRE(mem.load({0}, 13) == T);
        REQUIRE(mem.load({7}, 8) == T);
        REQUIRE(mem.load({8}, 5) == T);
        REQUIRE(mem.load({9}, 5) == T);
    }

    SECTION("Replacing") {
        D mem;
        mem.store({4}, 4, n1);
        mem.store({4}, 4, n2);

        REQUIRE(mem.load({4}, 4) == n2);

        REQUIRE(mem.load({0}, 4) == T);
        REQUIRE(mem.load({1}, 3) == T);
        REQUIRE(mem.load({2}, 2) == T);
        REQUIRE(mem.load({3}, 1) == T);
        REQUIRE(mem.load({8}, 4) == T);

        REQUIRE(mem.load({5}, 3) == NT);
        REQUIRE(mem.load({4}, 3) == NT);

        mem.store({8}, 4, n2);
        mem.store({8}, 4, n1);

        REQUIRE(mem.load({8}, 4) == n1);
        REQUIRE(mem.load({4}, 4) == n2);
    }

    SECTION("SecondHigherLarger") {
        D mem;
        mem.store({4}, 4, n1);
        mem.store({6}, 4, n2);

        REQUIRE(mem.load({6}, 4) == n2);

        REQUIRE(mem.load({4}, 2) == NT);
        REQUIRE(mem.load({4}, 3) == NT);
        REQUIRE(mem.load({4}, 6) == NT);
        REQUIRE(mem.load({5}, 1) == NT);
        REQUIRE(mem.load({5}, 2) == NT);
        REQUIRE(mem.load({5}, 5) == NT);
        REQUIRE(mem.load({7}, 3) == NT);
        
        REQUIRE(mem.load({0}, 4) == T);
        REQUIRE(mem.load({1}, 3) == T);
        REQUIRE(mem.load({2}, 2) == T);
        REQUIRE(mem.load({3}, 1) == T);
        REQUIRE(mem.load({10}, 4) == T);

        REQUIRE(mem.load({0}, 5) == T);
        REQUIRE(mem.load({0}, 9) == T);
        REQUIRE(mem.load({0}, 13) == T);
        REQUIRE(mem.load({4}, 8) == T);
        REQUIRE(mem.load({5}, 6) == T);
        REQUIRE(mem.load({6}, 5) == T);
    }
    
    SECTION("SecondLowerLarger") {
        D mem;
        mem.store({4}, 4, n1);
        mem.store({2}, 4, n2);

        D expected;
        expected.store({2}, 4, n2);
        expected.store({6}, 2, NT);
        REQUIRE(mem == expected);

        REQUIRE(mem.load({2}, 4) == n2);

        REQUIRE(mem.load({4}, 4) == NT);
        REQUIRE(mem.load({4}, 2) == NT);
        REQUIRE(mem.load({6}, 2) == NT);
        REQUIRE(mem.load({5}, 1) == NT);
        REQUIRE(mem.load({2}, 6) == NT);
        REQUIRE(mem.load({3}, 1) == NT);
        REQUIRE(mem.load({3}, 2) == NT);
        REQUIRE(mem.load({3}, 5) == NT);
        REQUIRE(mem.load({2}, 1) == NT);
        REQUIRE(mem.load({2}, 2) == NT);
        REQUIRE(mem.load({2}, 3) == NT);
        

        REQUIRE(mem.load({1}, 3) == T);
        REQUIRE(mem.load({0}, 4) == T);
        REQUIRE(mem.load({0}, 6) == T);
        REQUIRE(mem.load({0}, 9) == T);
        REQUIRE(mem.load({4}, 5) == T);
        REQUIRE(mem.load({5}, 4) == T);
        REQUIRE(mem.load({6}, 3) == T);
        REQUIRE(mem.load({10}, 4) == T);
    }

    SECTION("SecondHidesLarger") {
        D mem;
        mem.store({4}, 4, n1);
        mem.store({3}, 6, n2);

        REQUIRE(mem.load({3}, 6) == n2);
        
        D expected;
        expected.store({3}, 6, n2);
        REQUIRE(mem == expected);

        for (uint64_t i=1; i < 6; i++)
            REQUIRE(mem.load({3}, i) == NT);

        for (uint64_t s=4; s < 6; s++)
            for (uint64_t i=1; s+i < 3+6; i++)
                REQUIRE(mem.load({s}, i) == NT);
        
        for (uint64_t i=1; i < 8; i++)
            REQUIRE(mem.load({2}, i) == T);

        for (uint64_t s=3; s < 10; s++)
            REQUIRE(mem.load({s}, 10-s) == T);

        REQUIRE(mem.load({1}, 3) == T);
        REQUIRE(mem.load({0}, 4) == T);
        REQUIRE(mem.load({0}, 6) == T);
        REQUIRE(mem.load({0}, 9) == T);
        REQUIRE(mem.load({10}, 4) == T);
    }

    SECTION("SecondContained") {
        D mem;
        mem.store({4}, 4, n1);
        mem.store({5}, 2, n2);

        REQUIRE(mem.load({5}, 2) == n2);

        REQUIRE(mem.load({4}, 4) == NT);
        REQUIRE(mem.load({4}, 3) == NT);
        REQUIRE(mem.load({4}, 2) == NT);
        REQUIRE(mem.load({4}, 1) == NT);
        REQUIRE(mem.load({5}, 3) == NT);
        REQUIRE(mem.load({5}, 1) == NT);
        REQUIRE(mem.load({6}, 2) == NT);
        REQUIRE(mem.load({6}, 1) == NT);
        REQUIRE(mem.load({7}, 1) == NT);
        
        REQUIRE(mem.load({1}, 3) == T);
        REQUIRE(mem.load({0}, 4) == T);
        REQUIRE(mem.load({0}, 6) == T);
        REQUIRE(mem.load({0}, 9) == T);
        REQUIRE(mem.load({4}, 5) == T);
        REQUIRE(mem.load({5}, 4) == T);
        REQUIRE(mem.load({6}, 3) == T);
        REQUIRE(mem.load({10}, 4) == T);
    }

    SECTION("Permutations") {
        D mem;
        mem.store({0}, 4, n1);
        mem.store({4}, 4, n2);
        mem.store({8}, 4, n3);

        SECTION("840") {
            D mem1;
            mem1.store({8}, 4, n3); mem1.store({4}, 4, n2); mem1.store({0}, 4, n1);
            REQUIRE(mem == mem1);
        }
        SECTION("480") {
            D mem1;
            mem1.store({4}, 4, n2); mem1.store({8}, 4, n3); mem1.store({0}, 4, n1);
            REQUIRE(mem == mem1);
        }
        SECTION("408") {
            D mem1;
            mem1.store({4}, 4, n2); mem1.store({0}, 4, n1); mem1.store({8}, 4, n3);
            REQUIRE(mem == mem1);
        }
        SECTION("084") {
            D mem1;
            mem1.store({0}, 4, n1); mem1.store({8}, 4, n3); mem1.store({4}, 4, n2);
            REQUIRE(mem == mem1);
        }
    }
}
