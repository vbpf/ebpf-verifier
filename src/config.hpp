#pragma once

// defaults are in definition
struct global_options_t
{
    bool simplify;
    bool stats;
    bool check_semantic_reachability;
    bool print_invariants;
    bool print_failures;
    bool liveness;
};

extern global_options_t global_options;
