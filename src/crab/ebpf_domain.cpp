// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "crab_verifier_job.hpp"
using crab::domains::ebpf_domain_t;

const program_info& ebpf_domain_t::get_program_info() const { return m_job->get_program_info(); }
