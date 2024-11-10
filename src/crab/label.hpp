// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <algorithm>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include "crab_utils/num_safety.hpp"

constexpr char STACK_FRAME_DELIMITER = '/';

namespace crab {
struct label_t {
    std::string stack_frame_prefix; ///< Variable prefix when calling this label.
    int from{};                     ///< Jump source, or simply index of instruction
    int to{};                       ///< Jump target or -1
    std::string special_label;      ///< Special label for special instructions.

    explicit label_t(const int index, const int to = -1, std::string stack_frame_prefix = {}) noexcept
        : stack_frame_prefix(std::move(stack_frame_prefix)), from(index), to(to) {}

    static label_t make_jump(const label_t& src_label, const label_t& target_label) {
        return label_t{src_label.from, target_label.from, target_label.stack_frame_prefix};
    }

    static label_t make_increment_counter(const label_t& label) {
        // XXX: This is a hack to increment the loop counter.
        label_t res{label.from, label.to, label.stack_frame_prefix};
        res.special_label = "counter";
        return res;
    }

    std::strong_ordering operator<=>(const label_t& other) const = default;

    // no hash; intended for use in ordered containers.

    [[nodiscard]]
    constexpr bool isjump() const {
        return to != -1;
    }

    [[nodiscard]]
    int call_stack_depth() const {
        // The call stack depth is the number of '/' separated components in the label,
        // which is one more than the number of '/' separated components in the prefix,
        // hence two more than the number of '/' in the prefix, if any.
        if (stack_frame_prefix.empty()) {
            return 1;
        }
        return gsl::narrow<int>(2 + std::ranges::count(stack_frame_prefix, STACK_FRAME_DELIMITER));
    }

    static const label_t entry;
    static const label_t exit;
};

inline const label_t label_t::entry{-1};
inline const label_t label_t::exit{-2};

} // namespace crab

std::ostream& operator<<(std::ostream& os, const crab::label_t& label);
std::string to_string(crab::label_t const& label);
