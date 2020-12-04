#!/usr/bin/python3
# Copyright (c) Prevail Verifier contributors.
# SPDX-License-Identifier: MIT
#
# Usage: python3 hist.py results.csv [loads|stores|instructions|...]
import matplotlib.pyplot as plt
import numpy as np
from collections import Counter
import sys

if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
    print('Usage: {} FILE.csv [key] [uniq]')
    print('For example:')
    print('    python3 {} results.csv iterations False'.format(sys.argv[0]))
    sys.exit(64)


fig = plt.figure()
key = 'instructions' if len(sys.argv) < 3 else sys.argv[2]
uniq = True if len(sys.argv) < 4 else (sys.argv[3] == "True")

def plot_bar_from_counter(counter):
    ax = fig.add_subplot(1, 1, 1)

    x_coordinates = np.arange(len(counter))
    ax.bar(x_coordinates, counter.values(), align='center')
    
    ax.xaxis.set_tick_params(rotation=90)
    ax.xaxis.set_major_locator(plt.FixedLocator(x_coordinates))
    ax.xaxis.set_major_formatter(plt.FixedFormatter(list(counter.keys())))

    return ax

def get_hist(key, uniq):
    counter = Counter()
    seen = set()
    with open(sys.argv[1]) as f:
        head = next(f).split(',')
        d = [x.split(',') for x in f]
    p = head.index('project')
    h = head.index('hash')
    n = head.index(key)
    for line in d:
        if uniq and line[h] in seen: continue
        seen.add(line[h])
        counter[line[p]] += int(line[n])
    print(counter)
    return counter

plot_bar_from_counter(get_hist(key = key, uniq=uniq))
fig.tight_layout()
plt.show()
