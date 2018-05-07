import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

import lief
import numpy as np
from math import log, e

def entropy(labels, base=None):
    value,counts = np.unique(labels, return_counts=True)
    norm_counts = counts / counts.sum()
    base = e if base is None else base
    return -(norm_counts * np.log(norm_counts)/np.log(base)).sum()


# pebin = lief.PE.parse(filename='aa14c8e777-cape')
# pebin = lief.PE.parse(filename='test.exe')
# pebin = lief.PE.parse(filename='Locky.bin.mal')
# pebin = lief.PE.parse(filename='Shamoon.bin.mal')
pebin = lief.PE.parse(filename='Win32.Sofacy.A.bin.mal')


fig = plt.figure()
fig.set_figheight(5)
fig.set_figwidth(15)

sample_size = 400

for section in pebin.sections:
    data = section.content

    block_len = -(-len(data) // sample_size)

    shannon_samples = []

    i = 1
    prev_end = 0
    while prev_end <= len(data):

        block_start = prev_end
        block_end = i * block_len

        ent = entropy(data[ block_start : block_end ])
        shannon_samples.append(ent)

        prev_end = block_end+1
        i += 1


    plt.plot(shannon_samples, label=section.name)


plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)



# plt.xscale('log')
# plt.yscale('log')

fig.savefig('mpl-block-ent.png')
# plt.show()
