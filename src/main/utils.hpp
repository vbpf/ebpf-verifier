// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once

auto timed_execution(auto f) -> std::tuple<decltype(f()), double> {
    const clock_t begin = clock();

    auto res = f();

    const clock_t end = clock();

    double elapsed_secs = static_cast<double>(end - begin) / CLOCKS_PER_SEC;
    return std::make_tuple(std::move(res), elapsed_secs);
}
