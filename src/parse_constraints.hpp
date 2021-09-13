// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include <regex>
#include <set>
#include <string>
#include <vector>

#include "crab/linear_constraint.hpp"

std::vector<linear_constraint_t> parse_linear_constraints(const std::set<std::string>& constraints);
