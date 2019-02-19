
import matplotlib.pyplot as plt
import numpy as np
import sys

data = np.genfromtxt(sys.argv[1], delimiter=',', names=True)

n = 0
fig = plt.figure()

def plot(title, field, units, values):
    global n
    n += 1
    sp = fig.add_subplot(1, 2, n)
    sp.set_title(title)
    sp.set_xlabel(field)
    sp.set_ylabel(units)
    field = data[field]
    space = np.linspace(min(field), max(field), 2)

    for (label, deg, color) in values:
        arr = data[label]
        trendline = np.poly1d(np.polyfit(field, arr, deg))(space)
        sp.plot(space, trendline, color=color)
        sp.plot(field, arr, color=color, label=label,
                        marker='.',
                        markerfacecolor='None',
                        markeredgecolor=color,
                        linestyle = 'None')
    sp.legend()

plot("Sec vs stores", 'stores', 'Time (Sec)', [
    ('interval_sec' , 1, 'blue'),
    ('zoneCrab_sec' , 1, 'red'),
    ('zoneElina_sec', 1, 'orange'),
    ('polyElina_sec', 1, 'green'),
    #('octElina_sec' , 1, 'purple'),
])

plot("Memory vs stores", 'stores', 'Memory (KB)', [
    ('interval_kb' , 1, 'blue'),
    ('zoneCrab_kb' , 1, 'red'),
    ('zoneElina_kb', 1, 'orange'),
    ('polyElina_kb', 1, 'green'),
    #('octElina_kb' , 1, 'purple'),
])

plt.show()
