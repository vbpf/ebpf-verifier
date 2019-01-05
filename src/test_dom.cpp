#include "catch.hpp"

#include <iostream>

#include "ai_dom_set.hpp"
#include "ai_dom_rcp.hpp"

TEST_CASE( "fd_set_domain", "[dom][domain][fd]" ) {
    using D = FdSetDom;
    REQUIRE(D{3} == D{3});
    REQUIRE(!(D{4} == D{3}));

    auto top = [](){ return D{3, TOP}; };
    auto bot = [](){ return D{3}; };

    REQUIRE(D{3} == bot());
    REQUIRE_FALSE(bot() == top());

    REQUIRE((top() & bot()) == bot());
    REQUIRE((bot() & top()) == bot());

    REQUIRE((top() | bot()) == top());
    REQUIRE((bot() | top()) == top());
}

TEST_CASE( "numerical_set_domain", "[dom][domain]" ) {
    using D = NumDomSet;

    auto top = [](){ return D{TOP}; };
    auto bot = [](){ return D{}; };
    
    REQUIRE(D{} == bot());
    REQUIRE_FALSE(bot() == top());

    REQUIRE((top() & bot()) == bot());
    REQUIRE((bot() & top()) == bot());

    REQUIRE((top() | bot()) == top());
    REQUIRE((bot() | top()) == top());

    REQUIRE((top() & D(3)) == D(3));
    REQUIRE((top() | D(3)) == top());
    
    REQUIRE((bot() | D(3)) == D(3));
    REQUIRE((bot() & D(3)) == bot());

    REQUIRE((D(1) | D(2)) == D(1, 2));
    REQUIRE((D(2) | D(1)) == D(1, 2));

    REQUIRE(((D(1, 2)) & (D(2, 3))) == D(2));

    SECTION("add") {
        REQUIRE(D(1) + D(2) == D(3));
        REQUIRE(D(1, 2) + D(3) == D(4, 5));
        REQUIRE(D(1) + D(2, 3) == D(3, 4));
        REQUIRE(D(1, 2) + D(2, 3) == D(3, 4, 5));
        REQUIRE(D(TOP) + D(2) == D(TOP));
        REQUIRE(D(2) +  D(TOP) == D(TOP));
        REQUIRE(D(TOP) + D() == D());
        REQUIRE(D() +  D(TOP) == D());
        REQUIRE(D() + D(2) == D());
        REQUIRE(D(2) + D() == D());
    }

    SECTION("sub") {
        REQUIRE(D(3) - 2 == D(1));
        REQUIRE(D(4, 3) - 3 == D(0, 1));
        REQUIRE(D(3) - D(2, 3) == D(0, 1));
        REQUIRE(D(4, 3) - D(2, 3) == D(0, 1, 2));
        REQUIRE(D(TOP) - D(2) == D(TOP));
        REQUIRE(D(2) - D(TOP) == D(TOP));
        REQUIRE(D(TOP) - D() == D());
        REQUIRE(D() - D(TOP) == D());
        REQUIRE(D() - D(2) == D());
        REQUIRE(D(2) - D() == D());
    }

}

TEST_CASE( "offset_set_domain", "[dom][domain]" ) {
    using D = OffsetDomSet;

    auto top = [](){ return D{TOP}; };
    auto bot = [](){ return D{}; };

    SECTION("simple") {
        REQUIRE(D{} == bot());
        REQUIRE_FALSE(bot() == top());

        REQUIRE((top() & bot()) == bot());
        REQUIRE((bot() & top()) == bot());

        REQUIRE((top() | bot()) == top());
        REQUIRE((bot() | top()) == top());

        REQUIRE((D(1) | D(2)) == D(1, 2));
        REQUIRE((D(2) | D(1)) == D(1, 2));

        REQUIRE((D(1, 2) & D(2, 3)) == D(2));
        REQUIRE((D(2, 3) & D(1, 2)) == D(2));

        auto r1 = D(14);
        r1.assume(Condition::Op::LE, D(TOP));
        REQUIRE(r1 == D(14));
    }

    SECTION("add num") {
        REQUIRE(D(1) + 2 == D(3));
        REQUIRE(D(1, 2) + 3 == D(4, 5));
        REQUIRE(D(1) + NumDomSet(2, 3) == D(3, 4));
        REQUIRE(D(1, 2) + NumDomSet(2, 3) == D(3, 4, 5));
        REQUIRE(D() + NumDomSet(2) == D());
        REQUIRE(D(2) + NumDomSet() == D());
        REQUIRE(D(1) + NumDomSet(TOP) == D(TOP));
        REQUIRE(D() + NumDomSet(TOP) == D());
        REQUIRE(D(TOP) + NumDomSet() == D());
    }

    SECTION("sub num") {
        REQUIRE(D(3) - 2 == D(1));
        REQUIRE(D(4, 3) - 3 == D(0, 1));
        REQUIRE(D(3) - NumDomSet(2, 3) == D(0, 1));
        REQUIRE(D(4, 3) - NumDomSet(2, 3) == D(0, 1, 2));
        REQUIRE(D() - NumDomSet(2) == D());
        REQUIRE(D() - NumDomSet(TOP) == D());
        REQUIRE(D(1) - NumDomSet(TOP) == D(TOP));
        REQUIRE(D(TOP) - NumDomSet() == D());
        REQUIRE(D(TOP) - NumDomSet(TOP) == D(TOP));
    }

    SECTION("sub offset") {
        REQUIRE(D(4, 5) - D(3, 2) == NumDomSet(1, 2, 3));
        REQUIRE(D() - D(2) == NumDomSet());
        REQUIRE(D(2) - D() == NumDomSet());
        REQUIRE(D(TOP) - D(2) == NumDomSet(TOP));
        REQUIRE(D(TOP) - D(TOP) == NumDomSet(TOP));
        REQUIRE(D(1) - D(TOP) == NumDomSet(TOP));
        REQUIRE(D() - D(TOP) == NumDomSet());
        REQUIRE(D(TOP) - D() == NumDomSet());
    }
}

TEST_CASE( "rcp_domain", "[dom][domain]" ) {
    using D = RCP_domain;
    constexpr size_t NMAPS = 3;

    auto top = [](){ return D{NMAPS, TOP}; };
    auto bot = [](){ return D{NMAPS}; };
    const auto zero = D{NMAPS}.with_num(0);

    SECTION("simple") {
        REQUIRE(D{NMAPS} == bot());
        REQUIRE_FALSE(bot() == top());

        REQUIRE((top() & bot()) == bot());
        REQUIRE((bot() & top()) == bot());

        REQUIRE((top() | bot()) == top());
        REQUIRE((bot() | top()) == top());
    }
    

    SECTION("map fds") {
        /*
        auto fds = D{NMAPS}.with_num(0).with_fd(1).maps_from_fds();

        REQUIRE(fds == D{NMAPS}.with_num(0).with_map(1, 0));

        SECTION("eq 0") {
            D::assume(fds, Condition::Op::EQ, zero);
            REQUIRE(fds == D{NMAPS}.with_num(0));
        }

        SECTION("neq 0") {
            D::assume(fds, Condition::Op::NE, zero);
            REQUIRE(fds == D{NMAPS}.with_map(1, 0));
        }
        */
    }

    SECTION("other") {
        auto r1 = D{NMAPS}.with_packet(14);
        auto r9 = D{NMAPS}.with_packet(TOP);
        D::assume(r1, Condition::Op::LE, r9);
        REQUIRE(r1 == D{NMAPS}.with_packet(14));
    }

    SECTION("1 op 1") {
        const auto num_top = D{NMAPS}.with_num(TOP);
        const auto stack_top = D{NMAPS}.with_stack(TOP);
        const auto packet_top = D{NMAPS}.with_packet(TOP);
        const auto four = D{NMAPS}.with_num(4);
        const auto data = D{NMAPS}.with_packet(0);
        const auto packet_four = D{NMAPS}.with_packet(4);

        REQUIRE(num_top - num_top == num_top);
        REQUIRE(num_top + num_top == num_top);
        REQUIRE(num_top + four == num_top);
        REQUIRE(four + num_top == num_top);

        REQUIRE(stack_top - num_top == stack_top);
        REQUIRE(stack_top + num_top == stack_top);
        REQUIRE(stack_top + four == stack_top);
        REQUIRE(stack_top - stack_top == num_top);

        REQUIRE(data + four == packet_four);
        REQUIRE(four + data == packet_four);

        REQUIRE(data + num_top == packet_top);
        REQUIRE(num_top + data == packet_top);
    }
}
