from __future__ import division

import numpy as np
from math import e

# # Helper functions

# # Calculate entropy given a list
def shannon_ent(labels, base=256):
    value, counts = np.unique(labels, return_counts=True)
    norm_counts = counts / counts.sum()
    base = e if base is None else base
    return -(norm_counts * np.log(norm_counts)/np.log(base)).sum()
