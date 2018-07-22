#!/usr/bin/python

# Generate these graphs

## Pie chart of the size of the sections
# Line graph like kev has
# Heat map of sections of the pe file - looking for ent

import lief

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.ticker as ticker
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


## Helper functions
def shannon_ent(labels, base=256):
    value,counts = np.unique(labels, return_counts=True)
    norm_counts = counts / counts.sum()
    base = e if base is None else base
    return -(norm_counts * np.log(norm_counts)/np.log(base)).sum()

# Assign a colour to the section name. Static between samples
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

# Some samples may have a corrupt section name (e.g. 206c0533ce9bf83ecdf904bec2f3532d)
def fix_section_name(section, index):
        s_name = section.name
        if s_name == '' or s_name == None:
            print(str(index))
            s_name = 'sect_'+str(index)
        return s_name

# Read files as chunks
def get_chunk(fh, chunksize=8192):
    while True:
        chunk = fh.read(chunksize)
        if chunk:
            yield list(chunk)
        else:
            break

# # Global variables
__figformat__ = 'png'
__figsize__ = (12,4)
__figdpi__ = 100

# ## Ent per section
def section_ent_line(pebin, block_size=100, trend=False):
    # ## blocksize int:   content is divided into blocks, each block is sampled for shannon entropy. More blocks, greater resolution
    # ## trend bool/None: Show a trend line. True: Show trend line, False: Dont show trend line, None: Show ONLY the trend line

    data = []
    for i, section in enumerate(pebin.sections):

        s_name = fix_section_name(section, i)

        # Get a per section colour that is unique across all samples. e.g. same section name = same colour
        c1 = section_colour(s_name)

        # This gets the content block amounts and rounds up - so we always get 1 more than required
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

        # Customise the plt
        plt.axis([0,len(shannon_samples)-1, 0,1])
        plt.title('Section Entropy (sampled @ {:d}): {}'.format(block_size, pebin.name))
        plt.xlabel('Sample block')
        plt.ylabel('Entropy')
        plt.legend(loc='center left', bbox_to_anchor=(1, 0.5))

    return

# ## Histogram per byte
def section_byte_occurance_histogram(pebin, fig, ncols=2, ignore_0=True, bins=1, log=1, ordered=True):
    # ## ncols int:     Number of columns of graphs
    # ## ignore_0 bool: Remove x00 from the graph, sometimes this blows other results due to there being numerous amounts - also see log
    # ## bins int:      Sample bins
    # ## log int:       Amount of 'log' to apply to the graph
    # ## ordered bool:  Add an ordered histogram - show overall distribution


    ignore_0 = int(ignore_0)

    for i, section in enumerate(pebin.sections):

        s_name = fix_section_name(section, i)
        c1, c2 = section_colour(s_name, True)

        ax = fig.add_subplot( -(-len(pebin.sections) // ncols), ncols,i+1 )

        # Add a byte hist ordered 1 > 255
        ordered_row = []
        c = Counter(section.content)
        for x in range(ignore_0, 256):
            ordered_row.append(c[x])

        ax.bar((range(ignore_0,256)), ordered_row, bins, color=c1, log=log, zorder=1)

        # Add a byte hist ordered by occurance - shows general distribution
        if ordered:
            sorted_row = []
            c = Counter(section.content)
            for x in range(ignore_0, 256):
                sorted_row.append(c[x])

            sorted_row.sort()
            sorted_row.reverse()

            ax.bar((range(ignore_0,256)), sorted_row, bins, color=c2, log=log, zorder=0)

        ax.set_xlabel(s_name)

        # ax.set_title(s_name, fontsize='small')
        ax.set_xticks([])
        ax.set_xlim([0, 255])

    fig.suptitle('Byte histogram, per section. Ordered={}: {}'.format(str(ordered),pebin.name))
    fig.subplots_adjust(hspace=0.5)

    fig.legend(loc='center left', bbox_to_anchor=(1, 0.5))

# ## Entropy and byte occurance analysis
# binname: file to load and analyse
# figsize: specify size of the figure ouputted
# frmt: output filetype. Can be anything supported by matplotlib - png, svg, jpg
# figname: filename to save graph
# figsize: size to save figure, (width,height)
# chunks: how many chunks to split the file over. Smaller chunks give a more averaged graph, a larger number of chunks give more detail
# ibytes: a dict of interesting bytes wanting to be displayed on the graph. These can often show relationships and reason for dips or
#         increases in entropy at particular points. Bytes within each type are defined as lists of _decimals_, _not_ hex.

# Global variables specific to function
__chunks__ = 750
__ibytes__= "{\"0\'s\": [0] , \"Exploit\": [44, 144] }"
__ibytes_dict__ = json.loads(__ibytes__)
def file_ent(binname, frmt=__figformat__, figname=None, figsize=__figsize__, figdpi=__figdpi__, chunks=__chunks__, ibytes=__ibytes_dict__):

    if not figname:
        clean_binname = ''.join([c for c in binname if re.match(r'[\w\_\-\.]', c)])
        figname = 'file_ent-{}.{}'.format(clean_binname, frmt)

        log.debug('No name given. Generated: {}'.format(figname))

    fh = open(binname, 'rb')
    log.debug('Opening: {}'.format(binname))

    # # Calculate the overall chunksize 
    fs = os.fstat(fh.fileno()).st_size
    chunksize = -(-fs // chunks)
    nr_chunksize = fs / chunks
    log.debug('Filesize: {}, Chunksize (rounded): {}, Chunksize: {}, Chunks: {}'.format(fs, chunksize, nr_chunksize, chunks))

    shannon_samples = []

    # # Create byte occurrence dict if required
    if len(ibytes) > 0:
        byte_ranges = {key: [] for key in ibytes.keys()}
        log.debug('Parsed byte ranges: {}'.format(byte_ranges))

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


    # # Draw the graphs in order
    zorder=99

    # # Create the original figure
    fig, host = plt.subplots(figsize=figsize, dpi=figdpi)
    fig.subplots_adjust(right=0.75)

    # # Plot the entropy graph
    host.set_xlim([0, len(shannon_samples)+1])
    host.set_ylim([0, 1.05])
    host.plot(shannon_samples, label='Entropy', c=section_colour('Entropy'), zorder=zorder, linewidth=0.7)
    host.set_ylabel('Entropy\n(sampled over {} byte chunks)\n'.format(chunksize))
    host.set_xlabel('Raw file offset')
    host.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, pos: ('0x%x') % (int(x * nr_chunksize)))) 

    # # Plot individual byte percentages
    if len(ibytes) > 0:
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
        exebin = lief.parse(filepath=filename)
    except Exception as e:
        exebin = None

    if type(exebin) == lief.PE.Binary:

        # # Entrypoint (EP) pointer and vline
        v_ep = exebin.va_to_offset(exebin.entrypoint) / nr_chunksize
        host.axvline(x=v_ep, linestyle='--', c='r')
        host.text(x=v_ep, y=1.07, s='EP', rotation=90, verticalalignment='bottom', horizontalalignment='center')

        # # Section vlines
        for index, section in enumerate(exebin.sections):
            section_offset = section.offset / nr_chunksize

            host.axvline(x=section_offset, linestyle='--')
            host.text(x=section_offset, y=1.07, s=fix_section_name(section, index), rotation=90, verticalalignment='bottom', horizontalalignment='center')

    else:
        pass # NOT PE, but parse-able by lief, need to add more custom parsing


    # Add legends
    if len(ibytes) > 0:
        host.legend(loc=(1.1, 0.9))
    else:
        host.legend(loc=(1.02, 0.9))

    if len(ibytes) > 0:
        axBytePc.legend(loc=(1.1, 0.5))

    logo = plt.imread('cape.png')
    fig.figimage(logo, alpha=.5, zorder=99)

    plt.savefig(fname=figname, format=frmt, bbox_inches='tight')


if __name__ == '__main__':

    import os
    import sys
    import logging
    import argparse

    parser = argparse.ArgumentParser()

    parser.add_argument('-f', '--file', type=str, required=True, nargs='+', metavar='file.exe', help='Give me an entropy graph of this file!')
    parser.add_argument('-o', '--out', type=str, help='Graph output prefix - without extension!')
    parser.add_argument('--format', type=str, default=__figformat__, choices=['png', 'pdf', 'ps', 'eps','svg'], required=False, metavar='png', help='Graph output format')
    parser.add_argument('--figsize', type=int, nargs=2, default=__figsize__, metavar='#', help='Figure width and height in inches')
    parser.add_argument('--dpi', type=int, default=__figdpi__, metavar='100', help='Figure dpi')

    parser.add_argument('-v', '--verbose', action='store_true', help='Print debug information to stderr')

    subparsers = parser.add_subparsers(dest='graphtype')
    subparsers.required = True

    # # Arguments for the bytehist graph
    parser_bytehist = subparsers.add_parser('bytehist')


    # # Arguments for the ent graph
    parser_ent = subparsers.add_parser('ent')
    parser.add_argument('-c','--chunks', type=int, default=__chunks__, metavar='72', help='Figure dpi')
    parser.add_argument('--ibytes', type=str, default=__ibytes__, metavar='\"{\\\"0\'s\\\": [0] , \\\"Exploit\\\": [44, 144] }\"', help='JSON of bytes to include in the graph')

    args = parser.parse_args()


    ## # Verify arguments

    # # Set logging
    if args.verbose:
        logging.basicConfig(stream=sys.stderr, format='Verbose | %(levelname)s | %(message)s', level=logging.DEBUG)
    else:
        logging.basicConfig(stream=sys.stderr, format='*** %(levelname)s | %(message)s', level=logging.CRITICAL)

    log = logging.getLogger('binGraph')

    # # Does the file exist?
    for f in args.file:
        if not os.path.isfile(f):
            log.critical('Exiting, cannot find file: {}'.format(f))
            exit(1)
        else:
            log.debug('File exists: {}'.format(f))

    # # Parse ibytes
    args.ibytes = json.loads(args.ibytes)

    # # Iterate over all given files
    for index, file in enumerate(args.file):

        if len(args.file) > 0 and args.out:
            out_fname = ''.join([c for c in os.path.basename(file) if re.match(r'[\w\d\_\-\.]', c)])
            out_fname = '{}_{}_{}_{}-{}_{}.{}'.format(args.out, out_fname, args.graphtype, 'x'.join(map(str, args.figsize)), args.dpi, index, args.format)
        elif not args.out:
            out_fname = ''.join([c for c in os.path.basename(file) if re.match(r'[\w\d\_\-\.]', c)])
            out_fname = '{}.{}'.format(out_fname, args.format)
        else:
            out_fname = args.out

        log.debug('[+++] Generating: {}'.format(out_fname))

        if args.graphtype == 'ent':
            file_ent(binname=file, figname=out_fname, figsize=(args.figsize[0], args.figsize[1]), figdpi=args.dpi, ibytes=args.ibytes)

        log.debug('[+++] Done: {}'.format(out_fname))


    # pebin = lief.parse(filepath=filename)
    # plt.figure(figsize=fsize)
    # section_ent_line(pebin, block_size=50, trend=False)
    # plt.savefig(fname='section_ent_line-50.{}'.format(fmt), format=fmt, bbox_inches='tight')



    # pebin = lief.parse(filepath=filename)
    # fig = plt.figure(figsize=fsize)
    # section_byte_occurance_histogram(pebin, fig, ncols=3, ignore_0=True, bins=1, log=0, ordered=True)
    # fig.savefig(fname='section_byte_occurance_histogram.{}'.format(fmt), format=fmt, bbox_inches='tight')




