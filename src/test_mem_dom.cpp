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

template <typename ...Args>
MemDom mem(Args... lst) {
    return mem({lst...});
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
        const RCP_domain n = RCP_domain{}.with_num(5);
        D m = mem(D::Cell{0, 4, n});
        REQUIRE((m | m) == m);
    }
    
    const RCP_domain n1 = RCP_domain{}.with_num(5);
    const RCP_domain n2 = RCP_domain{}.with_num(9);
    const RCP_domain n3 = RCP_domain{}.with_num(3);

    SECTION("Nonoverlap") {
        D::Cell c1{0, 4, n1};
        D::Cell c2{4, 4, n2};
        D::Cell c3{8, 4, n3};
        D mem1 = mem(c1);
        D mem2 = mem(c2);
        D mem3 = mem(c3);

        D expected12 = mem(c1, c2);
        REQUIRE((mem1 | mem2) == expected12);
        REQUIRE((mem2 | mem1) == expected12);

        D expected13 = mem(c1, c3);
        REQUIRE((mem1 | mem3) == expected13);
        REQUIRE((mem3 | mem1) == expected13);

        D expected23 = mem(c2, c3);
        REQUIRE((mem2 | mem3) == expected23);
        REQUIRE((mem3 | mem2) == expected23);
    }

    SECTION("--xx__") {
        D m1 = mem({{4, 4, n1}});
        D m2 = mem({{6, 4, n2}});

        D expected = mem({{4, 2, NT}, {6, 2, NT}, {8, 2, NT}});
        REQUIRE((m1 | m2) == expected);
        REQUIRE((m2 | m1) == expected);
    }    

    SECTION("-xx-") {
        D m1 = mem({{4, 4, n1}});
        D m2 = mem({{3, 6, n2}});
        D expected = mem({{3, 1, NT}, {4, 4, NT}, {8, 1, NT}});

        REQUIRE((m1 | m2) == expected);
        REQUIRE((m2 | m1) == expected);
    }

    SECTION("with gap") {
        D m1 = mem({{4, 1, n1}, {6, 2, n1}});
        D m2 = mem({{3, 6, n2}});
        D expected = mem({{3, 1, NT}, {4, 1, NT}, {5, 1, NT}, {6, 2, NT}, {8, 1, NT}});

        REQUIRE((m1 | m2) == expected);
        REQUIRE((m2 | m1) == expected);
    }
}

TEST_CASE( "mem_dom_no_writes", "[dom][domain][mem]" ) {
    D m;
    REQUIRE(m.load({0}, 3) == T);
    REQUIRE(m.load({0}, 1) == T);
    REQUIRE(m.load({4}, 100) == T);
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
            D m;
            m.store({0}, 4, n);
            REQUIRE(m.load({0}, 4) == n);
        }
    }

    const RCP_domain n = RCP_domain{}.with_num(5);
    SECTION("WriteToStart") {
        D m;
        m.store({0}, 4, n);

        REQUIRE(m.load({0}, 4) == n);
        REQUIRE(m.load({0}, 3) == NT);
        REQUIRE(m.load({1}, 3) == NT);
        REQUIRE(m.load({0}, 5) == T);
        REQUIRE(m.load({1}, 4) == T);
    }

    SECTION("WriteToMiddle") {
        D m;
        m.store({1}, 4, n);

        REQUIRE(m.load({1}, 4) == n);

        REQUIRE(m.load({1}, 3) == NT);
        REQUIRE(m.load({2}, 3) == NT);

        REQUIRE(m.load({1}, 5) == T);
        REQUIRE(m.load({2}, 4) == T);
    }

    SECTION("WriteToEnd") {
        D m;
        m.store({STACK_SIZE-4}, 4, n);

        REQUIRE(m.load({STACK_SIZE-4}, 4) == n);

        REQUIRE(m.load({STACK_SIZE-4}, 3) == NT);
        REQUIRE(m.load({STACK_SIZE-3}, 3) == NT);

        REQUIRE(m.load({STACK_SIZE-4}, 5) == T);
        REQUIRE(m.load({STACK_SIZE-3}, 4) == T);
    }
}

TEST_CASE( "m_dom_two_writes", "[dom][domain][m]" ) {
    const RCP_domain n1 = RCP_domain{}.with_num(5);
    const RCP_domain n2 = RCP_domain{}.with_num(9);
    const RCP_domain n3 = RCP_domain{}.with_num(3);

    SECTION("NonOverlapping") {
        D m;
        m.store({4}, 4, n1);
        m.store({8}, 4, n2);

        D m1;
        m1.store({8}, 4, n2);
        m1.store({4}, 4, n1);
        REQUIRE(m == m1);

        REQUIRE(m.load({4}, 4) == n1);
        REQUIRE(m.load({8}, 4) == n2);

        REQUIRE(m.load({0}, 4) == T);
        REQUIRE(m.load({1}, 3) == T);
        REQUIRE(m.load({2}, 2) == T);
        REQUIRE(m.load({3}, 1) == T);
        REQUIRE(m.load({12}, 4) == T);

        REQUIRE(m.load({6}, 4) == NT);
        REQUIRE(m.load({4}, 8) == NT);

        REQUIRE(m.load({0}, 5) == T);
        REQUIRE(m.load({0}, 9) == T);
        REQUIRE(m.load({0}, 13) == T);
        REQUIRE(m.load({7}, 8) == T);
        REQUIRE(m.load({8}, 5) == T);
        REQUIRE(m.load({9}, 5) == T);
    }

    SECTION("Replacing") {
        D m;
        m.store({4}, 4, n1);
        m.store({4}, 4, n2);

        REQUIRE(m.load({4}, 4) == n2);

        REQUIRE(m.load({0}, 4) == T);
        REQUIRE(m.load({1}, 3) == T);
        REQUIRE(m.load({2}, 2) == T);
        REQUIRE(m.load({3}, 1) == T);
        REQUIRE(m.load({8}, 4) == T);

        REQUIRE(m.load({5}, 3) == NT);
        REQUIRE(m.load({4}, 3) == NT);

        m.store({8}, 4, n2);
        m.store({8}, 4, n1);

        REQUIRE(m.load({8}, 4) == n1);
        REQUIRE(m.load({4}, 4) == n2);
    }

    SECTION("SecondHigherLarger") {
        D m;
        m.store({4}, 4, n1);
        m.store({6}, 4, n2);

        REQUIRE(m.load({6}, 4) == n2);

        REQUIRE(m.load({4}, 2) == NT);
        REQUIRE(m.load({4}, 3) == NT);
        REQUIRE(m.load({4}, 6) == NT);
        REQUIRE(m.load({5}, 1) == NT);
        REQUIRE(m.load({5}, 2) == NT);
        REQUIRE(m.load({5}, 5) == NT);
        REQUIRE(m.load({7}, 3) == NT);
        
        REQUIRE(m.load({0}, 4) == T);
        REQUIRE(m.load({1}, 3) == T);
        REQUIRE(m.load({2}, 2) == T);
        REQUIRE(m.load({3}, 1) == T);
        REQUIRE(m.load({10}, 4) == T);

        REQUIRE(m.load({0}, 5) == T);
        REQUIRE(m.load({0}, 9) == T);
        REQUIRE(m.load({0}, 13) == T);
        REQUIRE(m.load({4}, 8) == T);
        REQUIRE(m.load({5}, 6) == T);
        REQUIRE(m.load({6}, 5) == T);
    }
    
    SECTION("SecondLowerLarger") {
        D m;
        m.store({4}, 4, n1);
        m.store({2}, 4, n2);

        D expected = mem({{2, 4, n2}, {6, 2, NT}});
        REQUIRE(m == expected);

        REQUIRE(m.load({2}, 4) == n2);

        REQUIRE(m.load({4}, 4) == NT);
        REQUIRE(m.load({4}, 2) == NT);
        REQUIRE(m.load({6}, 2) == NT);
        REQUIRE(m.load({5}, 1) == NT);
        REQUIRE(m.load({2}, 6) == NT);
        REQUIRE(m.load({3}, 1) == NT);
        REQUIRE(m.load({3}, 2) == NT);
        REQUIRE(m.load({3}, 5) == NT);
        REQUIRE(m.load({2}, 1) == NT);
        REQUIRE(m.load({2}, 2) == NT);
        REQUIRE(m.load({2}, 3) == NT);
        

        REQUIRE(m.load({1}, 3) == T);
        REQUIRE(m.load({0}, 4) == T);
        REQUIRE(m.load({0}, 6) == T);
        REQUIRE(m.load({0}, 9) == T);
        REQUIRE(m.load({4}, 5) == T);
        REQUIRE(m.load({5}, 4) == T);
        REQUIRE(m.load({6}, 3) == T);
        REQUIRE(m.load({10}, 4) == T);
    }

    SECTION("SecondHidesLarger") {
        D m;
        m.store({4}, 4, n1);
        m.store({3}, 6, n2);

        REQUIRE(m.load({3}, 6) == n2);
        
        D expected;
        expected.store({3}, 6, n2);
        REQUIRE(m == expected);

        for (uint64_t i=1; i < 6; i++)
            REQUIRE(m.load({3}, i) == NT);

        for (uint64_t s=4; s < 6; s++)
            for (uint64_t i=1; s+i < 3+6; i++)
                REQUIRE(m.load({s}, i) == NT);
        
        for (uint64_t i=1; i < 8; i++)
            REQUIRE(m.load({2}, i) == T);

        for (uint64_t s=3; s < 10; s++)
            REQUIRE(m.load({s}, 10-s) == T);

        REQUIRE(m.load({1}, 3) == T);
        REQUIRE(m.load({0}, 4) == T);
        REQUIRE(m.load({0}, 6) == T);
        REQUIRE(m.load({0}, 9) == T);
        REQUIRE(m.load({10}, 4) == T);
    }

    SECTION("SecondContained") {
        D m;
        m.store({4}, 4, n1);
        m.store({5}, 2, n2);

        REQUIRE(m.load({5}, 2) == n2);

        REQUIRE(m.load({4}, 4) == NT);
        REQUIRE(m.load({4}, 3) == NT);
        REQUIRE(m.load({4}, 2) == NT);
        REQUIRE(m.load({4}, 1) == NT);
        REQUIRE(m.load({5}, 3) == NT);
        REQUIRE(m.load({5}, 1) == NT);
        REQUIRE(m.load({6}, 2) == NT);
        REQUIRE(m.load({6}, 1) == NT);
        REQUIRE(m.load({7}, 1) == NT);
        
        REQUIRE(m.load({1}, 3) == T);
        REQUIRE(m.load({0}, 4) == T);
        REQUIRE(m.load({0}, 6) == T);
        REQUIRE(m.load({0}, 9) == T);
        REQUIRE(m.load({4}, 5) == T);
        REQUIRE(m.load({5}, 4) == T);
        REQUIRE(m.load({6}, 3) == T);
        REQUIRE(m.load({10}, 4) == T);
    }

    SECTION("Permutations") {
        D m = mem({
            {0, 4, n1},
            {4, 4, n2},
            {8, 4, n3}
        });

        SECTION("840") {
            D m1;
            m1.store({8}, 4, n3); m1.store({4}, 4, n2); m1.store({0}, 4, n1);
            REQUIRE(m == m1);
        }
        SECTION("480") {
            D m1;
            m1.store({4}, 4, n2); m1.store({8}, 4, n3); m1.store({0}, 4, n1);
            REQUIRE(m == m1);
        }
        SECTION("408") {
            D m1;
            m1.store({4}, 4, n2); m1.store({0}, 4, n1); m1.store({8}, 4, n3);
            REQUIRE(m == m1);
        }
        SECTION("084") {
            D m1;
            m1.store({0}, 4, n1); m1.store({8}, 4, n3); m1.store({4}, 4, n2);
            REQUIRE(m == m1);
        }
    }
}
