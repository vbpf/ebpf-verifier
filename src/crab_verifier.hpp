#pragma once

#include <string>
#include <vector>
#include <map>
#include <tuple>

#include "spec_type_descriptors.hpp"

#include "asm_cfg.hpp"

std::tuple<bool, double> abs_validate(Cfg const& simple_cfg, std::string domain_name, program_info info);

std::map<std::string, std::string> domain_descriptions();
