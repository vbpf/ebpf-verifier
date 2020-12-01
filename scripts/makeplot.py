#!/usr/bin/python3
# Copyright (c) Prevail Verifier contributors.
# SPDX-License-Identifier: MIT
#
# Usage: python3 makeplot.py results.csv [loads|stores|instructions|...]
import matplotlib.pyplot as plt
import numpy as np
import sys

if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
    print('Usage: {} FILE.csv [key] [showTrendline]')
    print('For example:')
    print('    python3 {} results.csv iterations False'.format(sys.argv[0]))
    sys.exit(64)

data = np.genfromtxt(sys.argv[1], delimiter=',', names=True)

n = 0
fig = plt.figure()
key = 'stores' if len(sys.argv) < 3 else sys.argv[2]
trendline = True if len(sys.argv) < 4 else (sys.argv[3] == "True")


def plot(title, field, units, suffix):
    global n
    n += 1
    sp = fig.add_subplot(1, 2, n)
    sp.set_title(title)
    sp.set_xlabel(field)
    sp.set_ylabel(units)
    field = data[field]
    space = np.linspace(min(field), max(field), 2)
    for label in data.dtype.fields:
        if not label.endswith(suffix): continue
        deg = 1
        arr = data[label]
        color = next(plt.gca()._get_lines.prop_cycler)['color']
        if trendline:
            sp.plot(space, np.poly1d(np.polyfit(field, arr, deg))(space), color=color)
        sp.plot(field, arr, color=color, label=label,
                        marker='.',
                        markerfacecolor='None',
                        linestyle = 'None')
    sp.legend()

plot("Sec vs " + key, key, 'Time (Sec)', '_sec')

plot("Memory vs " + key, key, 'Memory (KB)', '_kb')

plt.show()
