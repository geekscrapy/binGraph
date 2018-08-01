from __future__ import division

import numpy as np
from math import e
import re
import matplotlib.pyplot as plt 
import os
import sys

__pyver__ = sys.version_info[0]

# ## Global graphing default values
__figformat__ = 'png'   # Output format of saved figure
__figsize__ = (12,4)    # Size of figure in inches
__figdpi__ = 100        # DPI of figure
__showplt__ = False     # Show the plot interactively
__blob__ = False        # Treat all files as binary blobs. Disable intelligently parsing of file format specific features.

# # Helper functions

# # Calculate entropy given a list
def shannon_ent(labels, base=256):
    value, counts = np.unique(labels, return_counts=True)
    norm_counts = counts / counts.sum()
    base = e if base is None else base
    return -(norm_counts * np.log(norm_counts)/np.log(base)).sum()

# # Cleanup given filename
def clean_fname(fn):
    return ''.join([c for c in fn if re.match(r'[\w\_\-]', c)])

# # Add watermark
def add_watermark(fig):
    credit = plt.imread(os.path.dirname(os.path.realpath(__file__))+'/../credit.png')
    fig.figimage(credit, alpha=.5, zorder=99)
