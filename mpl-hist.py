import matplotlib.pyplot as plt
import lief
import numpy as np

pebin = lief.PE.parse(filename='Win32.Sofacy.A.bin.mal')
data = pebin.sections[0].content

plt.hist(data, bins=100, align='left', density=True, facecolor='g')

plt.savefig('test.png')
plt.show()
