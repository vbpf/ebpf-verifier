#include "crab/debug.hpp"

namespace crab {
bool CrabLogFlag = false;
std::set<std::string> CrabLog;

unsigned CrabVerbosity = 0;

bool CrabWarningFlag = true;
void CrabEnableWarningMsg(bool v) { CrabWarningFlag = v; }
} // namespace crab
