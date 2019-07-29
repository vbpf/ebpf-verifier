#include "crab/cfg.hpp"
#include "crab/types.hpp"
#include <iostream>

namespace crab {

void basic_block_t::write(std::ostream& o) const {
    o << m_label << ":\n";
    for (auto const& s : *this) {
        o << "  " << s << ";\n";
    }
    auto [it, et] = next_blocks();
    if (it != et) {
        o << "  "
          << "goto ";
        for (; it != et;) {
            o << *it;
            ++it;
            if (it == et) {
                o << ";";
            } else {
                o << ",";
            }
        }
    }
    o << "\n";
}

void basic_block_rev_t::write(std::ostream& o) const {
    o << label() << ":\n";
    for (auto const& s : *this) {
        o << "  " << s << ";\n";
    }
    o << "--> [";
    for (auto const& n : boost::make_iterator_range(next_blocks())) {
        o << n << ";";
    }
    o << "]\n";
}

} // namespace crab