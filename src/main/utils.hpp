// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

template<typename F>
auto timed_execution(F f) {
    clock_t begin = clock();

    const auto& res = f();

    clock_t end = clock();

    double elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;
    return std::make_tuple(res, elapsed_secs);
}
