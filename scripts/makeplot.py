#!/usr/bin/python3
# Usage: python3 makeplot.py results.csv [loads|stores|instructions|...]
import matplotlib.pyplot as plt
import numpy as np
import sys

data = np.genfromtxt(sys.argv[1], delimiter=',', names=True)

n = 0
fig = plt.figure()
key = 'stores' if len(sys.argv) < 2 else sys.argv[2]


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
        trendline = np.poly1d(np.polyfit(field, arr, deg))(space)
        color = next(plt.gca()._get_lines.prop_cycler)['color']
        sp.plot(space, trendline, color=color)
        sp.plot(field, arr, color=color, label=label,
                        marker='.',
                        markerfacecolor='None',
                        linestyle = 'None')
    sp.legend()

plot("Sec vs stores", key, 'Time (Sec)', '_sec')

plot("Memory vs stores", key, 'Memory (KB)', '_kb')

plt.show()
