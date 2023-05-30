// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#include "debug.hpp"

namespace crab {
bool CrabLogFlag = false;
std::set<std::string> CrabLog;

unsigned CrabVerbosity = 0;

bool CrabWarningFlag = false;
void CrabEnableWarningMsg(bool v) { CrabWarningFlag = v; }

} // namespace crab
