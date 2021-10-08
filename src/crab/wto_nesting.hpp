// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

// Bourdoncle, "Efficient chaotic iteration strategies with widenings", 1993
// uses the notation w(c) to refer to the set of heads of the nested components
// containing a vertex c.  This class holds such a set of heads.  The table
// mapping c to w(c) is stored outside the class, in wto_t._nesting.
class wto_nesting_t final {
    // To optimize insertion performance, the list of heads is stored in reverse
    // order, i.e., from innermost to outermost cycle.
    std::vector<label_t> _heads;

  public:
    wto_nesting_t(std::vector<label_t>&& heads) : _heads(std::move(heads)) {}

    // Test whether this nesting is a longer subset of another nesting.
    bool operator>(const wto_nesting_t& nesting) const {
        size_t this_size = this->_heads.size();
        size_t other_size = nesting._heads.size();
        if (this_size <= other_size) {
            // Can't be a superset.
            return false;
        }

        // Compare entries one at a time starting from the outermost
        // (i.e., end of the vectors).
        for (size_t index = 0; index < other_size; index++) {
            if (this->_heads[this_size - 1 - index] != nesting._heads[other_size - 1 - index]) {
                return false;
            }
        }
        return true;
    };

    // Output the nesting in order from outermost to innermost.
    friend std::ostream& operator<<(std::ostream& o, const wto_nesting_t& nesting) {
        for (auto it = nesting._heads.rbegin(); it != nesting._heads.rend(); it++) {
            o << *it << " ";
        }
        return o;
    }
};
