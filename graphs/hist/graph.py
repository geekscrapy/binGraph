"""
Byte histogram over all file
-------------------------------------------
abs_fpath:      Absolute file path - File to load and analyse
fname:          Filename

no_zero bool:   Remove 0x00 from the graph, sometimes this blows other results due to there being numerous amounts - also see log
width int:      Sample width
g_log bool:     Whether to apply a log scale to occurance axis
no_order bool:  Remove the ordered histogram - it shows overall distribution
"""

from __future__ import division

import os
import numpy as np
import matplotlib

import matplotlib.ticker as ticker
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator
from collections import Counter

import logging
log = logging.getLogger('hist')

# # Graph defaults
__no_zero__ = False
__width__ = 1
__g_log__ = True
__no_order__ = False

# Set args in args parse
def args_setup(arg_parser):

    arg_parser.add_argument('--no_zero', action='store_true', default=__no_zero__, help='Remove 0x00 from the graph, sometimes this blows other results due to there being numerous amounts - also see --no_log')
    arg_parser.add_argument('--width', type=int, default=__width__, metavar=__width__, help='Sample width')
    arg_parser.add_argument('--no_log', action='store_false', default=__g_log__, help='Do _not_ apply a log scale to occurance axis')
    arg_parser.add_argument('--no_order', action='store_true', default=__no_order__, help='Remove the ordered histogram - It shows overall distribution when on')

# Validate graph specific arguments
def args_validation(args):

    # # Test to see what matplotlib backend is setup
    backend = matplotlib.get_backend()
    if not backend == 'TkAgg':
        log.warning('{} matplotlib backend in use. This graph generation was tested with "TkAgg", bugs may lie ahead...'.format(backend))
    else:
        log.debug('Matplotlib backend: {}'.format(backend))

    # # Test to see if we should use defaults
    if args.graphtype == 'all':
        args.no_zero = __no_zero__
        args.width = __width__
        args.no_log = __g_log__
        args.no_order = __no_order__

def generate(abs_fpath, fname, no_zero=__no_zero__, width=__width__, g_log=__g_log__, no_order=__no_order__, **kwargs):

    file_array = []
    with open(abs_fpath, 'rb') as fh:
        for x in bytearray(fh.read()):
            file_array.append(x)

    log.debug('Read: "{}", length: {}'.format(fname, len(file_array)))

    log.debug('Ignore 0\'s: {}'.format(no_zero))
    no_zero = -int(no_zero)

    fig, ax = plt.subplots()

    # # Add a byte hist ordered 1 > 255
    ordered_row = []
    c = Counter(file_array)
    for x in range(no_zero, 256):
        ordered_row.append(c[x])

    ax.bar(np.array(list(range(no_zero, 256))), np.array(ordered_row), align='edge', width=width, label='Bytes', color='r', log=g_log, zorder=0, linewidth=0)
    log.debug('Graphed binary array')

    # # Add a byte hist ordered by occurrence - shows general distribution
    if not no_order:
        sorted_row = []
        c = Counter(file_array)
        for x in range(no_zero, 256):
            sorted_row.append(c[x])

        sorted_row.sort()
        sorted_row.reverse()

        ax.bar(np.array(list(range(no_zero, 256))), np.array(sorted_row), width=width, label='Ordered', color='b', log=g_log, zorder=1, alpha=.5, linewidth=0)
        log.debug('Graphed ordered binary array')

    # # Formatting and watermarking
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, pos: ('0x{:02X}'.format(int(x)))))
    ax.xaxis.set_major_locator(MaxNLocator(20))
    ax.set_xlabel('Bytes (0x00 included: {}, {})'.format((True if no_zero == 0 else False), ('width 1' if width == 1 else 'width: '+str(width))))
    ax.set_ylabel('Occurrence (log {})'.format(g_log))

    # Include 0x00 byte?
    if no_zero:
        ax.set_xlim(1,255)
        ax.set_xbound(lower=1, upper=255)
        log.debug('Ignoring 0x00, setting xlim/xbounds to (1,255)')
    else:
        ax.set_xlim(0,255)
        ax.set_xbound(lower=0, upper=255)
        log.debug('Setting xlim/xbounds to (0,255)')

    plt.legend(loc='upper center', ncol=3, bbox_to_anchor=(0.5, 1.07), framealpha=1)

    plt.title('Byte histogram: {}\n'.format(fname))

    return plt, {}
