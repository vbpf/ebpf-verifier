// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <vector>
#include <boost/pool/pool_alloc.hpp>

namespace Fast {

template <typename T>
using vector = std::vector<T, boost::pool_allocator<T>>;

}
