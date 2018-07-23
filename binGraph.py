#!/usr/bin/python

import lief

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.ticker as ticker
from matplotlib.ticker import MaxNLocator

from matplotlib import colors
from scipy.stats import entropy

from collections import Counter
import numpy as np
from math import log, e
import math
import hashlib
import statistics
import os, re
import json


# # Helper functions
def shannon_ent(labels, base=256):
    value,counts = np.unique(labels, return_counts=True)
    norm_counts = counts / counts.sum()
    base = e if base is None else base
    return -(norm_counts * np.log(norm_counts)/np.log(base)).sum()

# # Assign a colour to the section name. Static between samples
def section_colour(text, multi=False):

    name_colour = int('F'+hashlib.md5(text.encode('utf-8')).hexdigest()[:4], base=16)
    np.random.seed(int(name_colour))
    colour_main = np.random.rand(3,)

    # Sometimes we need more than one colour
    if multi:
        np.random.seed(int(name_colour)-255)
        colour_second = np.random.rand(3,)
        return colour_main, colour_second
    else:
        return colour_main

# # Some samples may have a corrupt section name (e.g. 206c0533ce9bf83ecdf904bec2f3532d)
def fix_section_name(section, index):
        s_name = section.name
        if s_name == '' or s_name == None:
            print(str(index))
            s_name = 'sect_'+str(index)
        return s_name

# # Read files as chunks
def get_chunk(fh, chunksize=8192):
    while True:
        chunk = fh.read(chunksize)
        if chunk:
            yield list(chunk)
        else:
            break

def clean_fname(fn):
    return ''.join([c for c in fn if re.match(r'[\w\_\-]', c)])

# ## Global variables
__figformat__ = 'png'
__figsize__ = (12,4)
__figdpi__ = 100


# ## Byte histogram over all file
# # -------------------------------------------
# # binname: file to load and analyse
# # figsize: specify size of the figure ouputted
# # frmt: output filetype. Can be anything supported by matplotlib - png, svg, jpg
# # figname: filename to save graph
# # figsize: size to save figure, (width,height)

# # ignore_0 bool: Remove x00 from the graph, sometimes this blows other results due to there being numerous amounts - also see log
# # bins int:      Sample bins
# # g_log int:       Amount of 'log' to apply to the graph
# # ordered bool:  Add an ordered histogram - show overall distribution

# # Global variables specific to function
__ignore_0__ = True
__bins__ = 1
__g_log__ = 1
__ordered__ = True
def bin_hist(binname, frmt=__figformat__, figname=None, figsize=__figsize__, figdpi=__figdpi__, ignore_0=__ignore_0__, bins=__bins__, g_log=__g_log__, ordered=__ordered__):

    if not figname:
        figname = 'bin_hist-{}.{}'.format(clean_fname(binname), frmt)
        log.debug('No name given. Generated: {}'.format(figname))

    file_array = []
    with open(binname, 'rb') as fh:
        for x in fh.read():
            file_array.append(x)

    log.debug('Read: "{}", length: {}'.format(binname, len(file_array)))

    ignore_0 = int(ignore_0)
    log.debug('Ignore 0\'s: {}'.format(ignore_0))

    fig, ax = plt.subplots(figsize=figsize, dpi=figdpi)

    if ignore_0:
        ax.set_xlim(1,255)
        log.debug('Setting xlim to (1,255)')
    else:
        ax.set_xlim(0,255)
        log.debug('Setting xlim to (0,255)')

    # # Add a byte hist ordered 1 > 255
    ordered_row = []
    c = Counter(file_array)
    for x in range(ignore_0, 256):
        ordered_row.append(c[x])

    ax.bar((range(ignore_0, 256)), ordered_row, bins, label='Bytes', color='r', log=g_log, zorder=1)
    log.debug('Graphed binary array')

    # # Add a byte hist ordered by occurance - shows general distribution
    if ordered:
        sorted_row = []
        c = Counter(file_array)
        for x in range(ignore_0, 256):
            sorted_row.append(c[x])

        sorted_row.sort()
        sorted_row.reverse()

        ax.bar((range(ignore_0,256)), sorted_row, bins, label='Ordered', color='b', log=g_log, zorder=0)
        log.debug('Graphed ordered binary array')

    ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, pos: ('0x%x') % (int(x))))
    ax.xaxis.set_major_locator(MaxNLocator(20))
    ax.set_xlabel('Bytes')
    ax.set_ylabel('Occurance (log {})'.format(g_log))

    plt.legend(loc=(1.03, 0.9))

    fig.suptitle('Byte histogram: {}'.format(os.path.basename(binname)))
    fig.subplots_adjust(hspace=0.5)

    logo = plt.imread('cape.png')
    fig.figimage(logo, alpha=.5, zorder=99)

    plt.savefig(fname=figname, format=frmt, bbox_inches='tight')
    log.debug('Saved to: "{}"'.format(figname))

    if False:
        plt.show()

    plt.clf()
    plt.cla()
    plt.close(fig)


# ## Entropy and byte occurance analysis over all file
# # -------------------------------------------
# # binname: file to load and analyse
# # figsize: specify size of the figure ouputted
# # frmt: output filetype. Can be anything supported by matplotlib - png, svg, jpg
# # figname: filename to save graph
# # figsize: size to save figure, (width,height)

# # chunks int: how many chunks to split the file over. Smaller chunks give a more averaged graph, a larger number of chunks give more detail
# # ibytes dicts of lists: a dict of interesting bytes wanting to be displayed on the graph. These can often show relationships and reason for dips or
# #                        increases in entropy at particular points. Bytes within each type are defined as lists of _decimals_, _not_ hex.

# # Global variables specific to function
__chunks__ = 750
__ibytes__= '{"0\'s": [0], "Printable ASCII": [32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126], "Exploit": [44, 144]}'
__ibytes_dict__ = json.loads(__ibytes__)
def bin_ent(binname, frmt=__figformat__, figname=None, figsize=__figsize__, figdpi=__figdpi__, chunks=__chunks__, ibytes=__ibytes_dict__):

    if not figname:
        figname = 'bin_ent-{}.{}'.format(clean_fname(binname), frmt)
        log.debug('No name given. Generated: {}'.format(figname))

    fh = open(binname, 'rb')
    log.debug('Opening: "{}"'.format(binname))

    # # Calculate the overall chunksize 
    fs = os.fstat(fh.fileno()).st_size
    chunksize = -(-fs // chunks)
    nr_chunksize = fs / chunks
    log.debug('Filesize: {}, Chunksize (rounded): {}, Chunksize: {}, Chunks: {}'.format(fs, chunksize, nr_chunksize, chunks))

    shannon_samples = []

    # # Create byte occurrence dict if required
    if len(ibytes) > 0:
        byte_ranges = {key: [] for key in ibytes.keys()}

    log.debug('Going for iteration over bytes with chunksize {}'.format(chunksize))
    log.debug('Using ibytes: {}'.format(ibytes))

    prev_ent = 0
    for chunk in get_chunk(fh, chunksize=chunksize):

        # # Calculate ent
        real_ent = shannon_ent(chunk)
        ent = statistics.median([real_ent, prev_ent])
        prev_ent = real_ent
        ent = real_ent
        shannon_samples.append(ent)

        # # Calculate percentages of given bytes, if provided
        if len(ibytes) > 0:
            cbytes = Counter(chunk)
            for label, b_range in ibytes.items():

                occurance = 0
                for b in b_range:
                    occurance += cbytes[b]

                byte_ranges[label].append((float(occurance)/float(len(chunk)))*100)

    fh.close()
    log.debug('Closed: "{}"'.format(binname))

    # # Draw the graphs in order
    zorder=99

    # # Create the original figure
    fig, host = plt.subplots(figsize=figsize, dpi=figdpi)
    fig.subplots_adjust(right=0.75)

    # # Plot the entropy graph
    host.set_xlim([0, len(shannon_samples)+1])
    host.set_ylim([0, 1.05])

    log.debug('Plotting shannon samples')
    host.plot(shannon_samples, label='Entropy', c=section_colour('Entropy'), zorder=zorder, linewidth=1)

    host.set_ylabel('Entropy\n'.format(chunksize))
    host.set_xlabel('Raw file offset')
    host.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, pos: ('0x%x') % (int(x * nr_chunksize)))) 
    host.xaxis.set_major_locator(MaxNLocator(10))
    plt.xticks(rotation=-10, ha='left')


    # # Plot individual byte percentages
    if len(ibytes) > 0:
        log.debug('Plotting ibytes')

        axBytePc = host.twinx()
        axBytePc.set_ylim([-0.3, 101])
        axBytePc.set_ylabel('Occurance of bytes (%)')
        axBytePc.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, pos: ('%i%%') % (x)))

        for label, percentages in byte_ranges.items():
            zorder -= zorder
            c = section_colour(label)
            axBytePc.plot(percentages, label=label, c=c, zorder=zorder, linewidth=0.7)

    # # Filetype specific additions
    try:
        exebin = lief.parse(filepath=binname)
        log.debug('Parsed with lief as {}'.format(exebin.format))

    except Exception as e:
        exebin = None
        log.debug('Failed to parse with lief: {}'.format(e))

    if exebin:
        if type(exebin) == lief.PE.Binary:

            log.debug('Adding PE customisations')

            # # Entrypoint (EP) pointer and vline
            v_ep = exebin.va_to_offset(exebin.entrypoint) / nr_chunksize
            host.axvline(x=v_ep, linestyle='--', c='r')
            host.text(x=v_ep, y=1.07, s='EP', rotation=90, verticalalignment='bottom', horizontalalignment='center')

            # # Section vlines
            for index, section in enumerate(exebin.sections):

                log.debug('{}: {}'.format(fix_section_name(section, index), section.offset))

                section_offset = section.offset / nr_chunksize

                host.axvline(x=section_offset, linestyle='--')
                host.text(x=section_offset, y=1.07, s=fix_section_name(section, index), rotation=90, verticalalignment='bottom', horizontalalignment='center')

        else:
            log.debug('Not currently customised: {}'.format(exebin.format))


    # Add legends
    if len(ibytes) > 0:
        host.legend(loc=(1.1, 0.9))
    else:
        host.legend(loc=(1.02, 0.9))

    if len(ibytes) > 0:
        axBytePc.legend(loc=(1.1, 0.5))

    logo = plt.imread('cape.png')

    fig.suptitle('Binary entropy (sampled over {} byte chunks): {}'.format(chunksize, os.path.basename(binname)), y=1.1)
    fig.subplots_adjust(hspace=0.5)

    fig.figimage(logo, alpha=.5, zorder=99)

    plt.savefig(fname=figname, format=frmt, bbox_inches='tight')
    log.debug('Saved to: "{}"'.format(figname))

    if False:
        plt.show()

    plt.clf()
    plt.cla()
    plt.close(fig)


def section_graphs():
    # ## Ent per section
    # # -------------------------------------------
    # # blocksize int:   content is divided into blocks, each block is sampled for shannon entropy. More blocks, greater resolution
    # # trend bool/None: Show a trend line. True: Show trend line, False: Dont show trend line, None: Show ONLY the trend line
    def section_ent_line(pebin, block_size=100, trend=False):

        data = []
        for i, section in enumerate(pebin.sections):

            s_name = fix_section_name(section, i)

            # # Get a per section colour that is unique across all samples. e.g. same section name = same colour
            c1 = section_colour(s_name)

            # # This gets the content block amounts and rounds up - so we always get 1 more than required
            block_len = -(-len(section.content) // block_size)

            shannon_samples = []

            i = 1
            prev_end = 0
            prev_ent = 0
            while prev_end <= len(section.content):

                block_start = prev_end
                block_end = i * block_len

                real_ent = shannon_ent(section.content[ block_start : block_end ])

                # Smooth
                ent = statistics.median([real_ent, prev_ent])
                prev_ent = real_ent


                shannon_samples.append(ent)

                prev_end = block_end+1
                i += 1

            if trend or trend == None:
                x = range(len(shannon_samples))
                y = shannon_samples

                z = np.polyfit(x, y, 15)
                f = np.poly1d(z)

                x_new = np.linspace(x[0], x[-1], block_size)
                y_new = f(x_new)

                plt.plot(x_new,y_new, label=s_name, c=c1)

            if not trend == None:
                plt.plot(shannon_samples, label=s_name, c=c1)

            # # Customise the plt
            plt.axis([0,len(shannon_samples)-1, 0,1])
            plt.title('Section Entropy (sampled @ {:d}): {}'.format(block_size, pebin.name))
            plt.xlabel('Sample block')
            plt.ylabel('Entropy')
            plt.legend(loc='center left', bbox_to_anchor=(1, 0.5))

        return


    # ## Byte histogram per section
    # # -------------------------------------------
    # # ncols int:     Number of columns of graphs
    # # ignore_0 bool: Remove x00 from the graph, sometimes this blows other results due to there being numerous amounts - also see log
    # # bins int:      Sample bins
    # # log int:       Amount of 'log' to apply to the graph
    # # ordered bool:  Add an ordered histogram - show overall distribution
    def section_byte_occurance_histogram(pebin, fig, ncols=2, ignore_0=True, bins=1, log=1, ordered=True):

        ignore_0 = int(ignore_0)

        for i, section in enumerate(pebin.sections):

            s_name = fix_section_name(section, i)
            c1, c2 = section_colour(s_name, True)

            ax = fig.add_subplot( -(-len(pebin.sections) // ncols), ncols,i+1 )

            # # Add a byte hist ordered 1 > 255
            ordered_row = []
            c = Counter(section.content)
            for x in range(ignore_0, 256):
                ordered_row.append(c[x])

            ax.bar((range(ignore_0,256)), ordered_row, bins, color=c1, log=log, zorder=1)

            # # Add a byte hist ordered by occurance - shows general distribution
            if ordered:
                sorted_row = []
                c = Counter(section.content)
                for x in range(ignore_0, 256):
                    sorted_row.append(c[x])

                sorted_row.sort()
                sorted_row.reverse()

                ax.bar((range(ignore_0,256)), sorted_row, bins, color=c2, log=log, zorder=0)

            ax.set_xlabel(s_name)

            # # ax.set_title(s_name, fontsize='small')
            ax.set_xticks([])
            ax.set_xlim([0, 255])

        fig.suptitle('Byte histogram, per section: {}'.format(str(ordered),pebin.name))
        fig.subplots_adjust(hspace=0.5)

        fig.legend(loc='center left', bbox_to_anchor=(1, 0.5))



if __name__ == '__main__':

    import os
    import sys
    import logging
    import argparse

    parser = argparse.ArgumentParser()

    parser.add_argument('-f', '--file', type=str, required=True, nargs='+', metavar='malware.exe', help='Give me a graph of this file. See - if this is the only argument specified.')
    parser.add_argument('-', dest='__dummy', action="store_true", help='*** Required if --file or -f is the only argument given before a graph type is given (it\'s greedy!). E.g. "binGraph.py --file mal.exe - bin_ent"')
    parser.add_argument('-p', '--prefix', type=str, help='Saved graph output filename (without extension)')
    parser.add_argument('-d', '--save_dir', type=str, default=os.getcwd(), metavar='/data/graphs/', help='Where to save the graph files')
    parser.add_argument('--format', type=str, default=__figformat__, choices=['png', 'pdf', 'ps', 'eps','svg'], required=False, metavar='png', help='Graph output format')
    parser.add_argument('--figsize', type=int, nargs=2, default=__figsize__, metavar='#', help='Figure width and height in inches')
    parser.add_argument('--dpi', type=int, default=__figdpi__, metavar=__figdpi__, help='Figure dpi')
    parser.add_argument('-v', '--verbose', action='store_true', help='Print debug information to stderr')


    subparsers = parser.add_subparsers(dest='graphtype', help='Graph type to generate')
    subparsers.required = True

    parser_all = subparsers.add_parser('all')

    # # Arguments for the ent graph
    parser_bin_ent = subparsers.add_parser('bin_ent')
    parser_bin_ent.add_argument('-c','--chunks', type=int, default=__chunks__, metavar='72', help='Defines how many chunks the binary is split into (and therefore the amount of bytes submitted for shannon sampling per time)')
    parser_bin_ent.add_argument('--ibytes', type=str, default=__ibytes__, metavar='\"{\\\"0\'s\\\": [0] , \\\"Exploit\\\": [44, 144] }\"', help='JSON of bytes to include in the graph')

    # # Arguments for the bytehist graph
    parser_bin_hist = subparsers.add_parser('bin_hist')
    parser_bin_hist.add_argument('--ignore_0', action='store_true', default=__ignore_0__, help='Remove x00 from the graph, sometimes this blows other results due to there being numerous amounts - also see --log')
    parser_bin_hist.add_argument('--bins', type=int, default=__bins__, metavar=__bins__, help='Sample bins')
    parser_bin_hist.add_argument('--log', type=int, default=__g_log__, metavar=__g_log__, help='Amount of \'log\' to apply to the graph')
    parser_bin_hist.add_argument('--ordered', action='store_true', default=__ordered__, help='Add an ordered histogram - show overall distribution')

    args = parser.parse_args()

    ## # Verify arguments

    # # Set logging
    if args.verbose:
        logging.basicConfig(stream=sys.stderr, format='Verbose | %(levelname)s | %(message)s', level=logging.DEBUG)
    else:
        logging.basicConfig(stream=sys.stderr, format='*** %(levelname)s | %(message)s', level=logging.CRITICAL)

    log = logging.getLogger('binGraph')

    # # Do the files exist?
    files = []
    for f in args.file:

        if not os.path.isfile(f):
            log.critical('Not a file, skipping: "{}"'.format(f))
        else:
            log.debug('File exists: "{}"'.format(f))
            files.append(f)

    # # Is the save_dir actually a dirctory?
    args.save_dir = os.path.abspath(args.save_dir)
    if not os.path.isdir(args.save_dir):
        log.critical('--save_dir ({}), is not a directory...'.format(args.save_dir))
        exit(1)
    else:
        log.debug('Saving graphs to directory "{}"'.format(args.save_dir))

    # # Detect if all graphs are being requested + set required defaults
    graph_types = []
    if args.graphtype == 'all':

        graph_types.append('bin_ent')
        args.ibytes = __ibytes__

        graph_types.append('bin_hist')
        args.ignore_0 = __ignore_0__
        args.bins = __bins__
        args.log = __g_log__
        args.ordered = __ordered__

    else:
        graph_types = [args.graphtype]

    # # Iterate over all given files
    for index, file in enumerate(files):

        log.debug('+++ Processing: "{}"'.format(file))

        clean_fn = clean_fname(os.path.basename(file))

        if len(args.file) > 0 and args.prefix:
            save_fn = '{arg_prefix}-{clean_fn}-{{}}-{figsize}_{dpi}-{index}.{format}'.format(arg_prefix=args.prefix, clean_fn=clean_fn, figsize='x'.join(map(str, args.figsize)), dpi=args.dpi, index=index, format=args.format)
        elif len(args.file) > 0 and not args.prefix:
            save_fn = '{clean_fn}-{{}}-{figsize}_{dpi}-{index}.{format}'.format(clean_fn=clean_fn, figsize='x'.join(map(str, args.figsize)), dpi=args.dpi, index=index, format=args.format)

        elif len(args.file) == 1 and args.prefix:
            save_fn = '{arg_prefix}.{format}'.format(arg_prefix=args.prefix, format=args.format)
        elif len(args.file) == 1 and not args.prefix:
            save_fn = '{clean_fn}-{{}}-{figsize}_{dpi}-{index}.{format}'.format(clean_fn=clean_fn, figsize='x'.join(map(str, args.figsize)), dpi=args.dpi, index=index, format=args.format)

        save_fn = os.path.join(args.save_dir, save_fn)

        if 'bin_ent' in graph_types:
            __save_fn__ = save_fn.format('bin_ent')
            log.debug('+ Generating bin_ent from "{}"'.format(file))
            bin_ent(binname=file, frmt=args.format, figname=__save_fn__, figsize=(args.figsize[0], args.figsize[1]), figdpi=args.dpi, chunks=args.chunks, ibytes=json.loads(args.ibytes))

        if 'bin_hist' in graph_types:
            __save_fn__ = save_fn.format('bin_hist')
            log.debug('+ Generating bin_hist from "{}"'.format(file))
            bin_hist(binname=file, frmt=args.format, figname=__save_fn__, figsize=(args.figsize[0], args.figsize[1]), figdpi=args.dpi, ignore_0=args.ignore_0, bins=args.bins, g_log=args.log, ordered=args.ordered)

        log.debug('+++ Complete: "{}"'.format(file))



