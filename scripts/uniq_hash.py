#!/usr/bin/python3
# Copyright (c) Prevail Verifier contributors.
# SPDX-License-Identifier: MIT
import fileinput
import sys

f = fileinput.input()
header = next(f)
sys.stdout.write(header)
h_index = header.split(',').index('hash')

seen = set()
for line in f:
    h = line.split(',')[h_index]
    if h in seen: continue
    seen.add(h)
    sys.stdout.write(line)
