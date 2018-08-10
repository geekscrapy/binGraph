"""

## Byte histogram over all file
-------------------------------------------
binname:     File to load and analyse
figsize:     Specify size of the figure ouputted
frmt:        Output filetype. Can be anything supported by matplotlib - png, svg, jpg
figname:     Filename to save graph
figsize:     Size to save figure, (width,height)
showplt:    Show the graph interactively, disables saving to a file

no_zero bool:  Remove 0x00 from the graph, sometimes this blows other results due to there being numerous amounts - also see log
width int:     Sample width
g_log bool:    Whether to apply a log scale to occurance axis
no_order bool: Remove the ordered histogram - it shows overall distribution

"""
from __future__ import division

# # Get common graph defaults
from graphs.global_defaults import __figformat__, __figsize__, __figdpi__, __showplt__

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from matplotlib.ticker import MaxNLocator
from collections import Counter
import numpy as np

import os

import logging
log = logging.getLogger()

# # Graph defaults
__no_zero__ = False
__width__ = 1
__g_log__ = True
__no_order__ = False

# Set args in args parse
def args_setup(subparser):

    parser_bin_hist = subparser.add_parser('bin_hist')
    parser_bin_hist.add_argument('--no_zero', action='store_true', default=__no_zero__, help='Remove 0x00 from the graph, sometimes this blows other results due to there being numerous amounts - also see --no_log')
    parser_bin_hist.add_argument('--width', type=int, default=__width__, metavar=__width__, help='Sample width')
    parser_bin_hist.add_argument('--no_log', action='store_false', default=__g_log__, help='Do _not_ apply a log scale to occurance axis')
    parser_bin_hist.add_argument('--no_order', action='store_true', default=__no_order__, help='Remove the ordered histogram - It shows overall distribution when on')

# Validate graph specific arguments
def args_validation(args):

    # # Test to see what matplotlib backend is setup
    backend = matplotlib.get_backend()
    if not backend == 'TkAgg':
        log.warning('{} matplotlib backend in use. This graph generation was tested with XXX, bugs may lie ahead...'.format(backend))
    else:
        log.debug('Matplotlib backend: {}'.format(backend))

    # # Test to see if we should use defaults
    if args.graphtype == 'all':
        args.no_zero = __no_zero__
        args.width = __width__
        args.no_log = __g_log__
        args.no_order = __no_order__

def generate(binname, frmt=__figformat__, figname=None, figsize=__figsize__, figdpi=__figdpi__, showplt=__showplt__, no_zero=__no_zero__, width=__width__, g_log=__g_log__, no_order=__no_order__):

    if not figname:
        figname = 'bin_hist-{}.{}'.format(clean_fname(binname), frmt)
        log.info('No name given. Generated: {}'.format(figname))

    file_array = []
    with open(binname, 'rb') as fh:
        for x in bytearray(fh.read()):
            file_array.append(x)

    log.debug('Read: "{}", length: {}'.format(binname, len(file_array)))

    no_zero = int(no_zero)
    log.debug('Ignore 0\'s: {}'.format(no_zero))

    fig, ax = plt.subplots(figsize=figsize, dpi=figdpi)

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

    plt.title('Byte histogram: {}\n'.format(os.path.basename(binname)))

    # Add watermark
    add_watermark(fig)

    fig.tight_layout()

    if showplt:
        log.debug('Opening graph interactively')
        plt.show()
    else:
        plt.savefig(figname, format=frmt, dpi=figdpi, bbox_inches='tight')
        log.debug('Saved to: "{}"'.format(figname))

    plt.clf()
    plt.cla()
    plt.close()
