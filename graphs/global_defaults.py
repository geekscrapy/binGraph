import sys

__pyver__ = sys.version_info[0]

# ## Global graphing default values
__figformat__ = 'png'   # Output format of saved figure
__figsize__ = (12,4)    # Size of figure in inches
__figdpi__ = 100        # DPI of figure
__showplt__ = False     # Show the plot interactively
__blob__ = False        # Treat all files as binary blobs. Disable intelligently parsing of file format specific features.
