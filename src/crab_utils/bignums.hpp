// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#ifdef BIGNUMS_GMP
// Use the GMP library, which is under LGPLv3 and GNU GPLv2.
# include "crab_utils/bignums_gmp.hpp"
#else
// Use the Boost library, which is under BSL-1.0 (Boost Software License).
# include "crab_utils/bignums_boost.hpp"
#endif
