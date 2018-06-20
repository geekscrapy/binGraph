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
            s_name = 'unknown_'+str(index)
        return s_name

# Read files as chunks
def get_chunk(fh, chunksize=8192):
    while True:
        chunk = fh.read(chunksize)
        if chunk:
            yield list(chunk)
        else:
            break


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
def file_ent(binname, frmt='png', figname=None, figsize=(12,4), chunks=750, ibytes={'0\'s':[0], 'Printable':list(range(0,128)), 'Exploit':[44,144]}):

    if not figname:
        clean_binname = ''.join([c for c in binname if re.match(r'[\w\_\-\.]', c)])
        figname = 'file_ent-{}.{}'.format(clean_binname, frmt)

    fh = open(binname, 'rb')

    # Calculate the overall chunksize 
    fs = os.fstat(fh.fileno()).st_size
    chunksize = -(-fs // chunks)

    shannon_samples = []

    # Create byte occurance dict if required
    if len(ibytes) > 0:
        byte_ranges = {key: [] for key in ibytes.keys()}


    prev_ent = 0
    for chunk in get_chunk(fh, chunksize=chunksize):

        # Calculate ent
        real_ent = shannon_ent(chunk)
        ent = statistics.median([real_ent, prev_ent])
        prev_ent = real_ent
        ent = real_ent
        shannon_samples.append(ent)

        # Calculate percentages of given bytes, if provided
        if len(ibytes) > 0:
            cbytes = Counter(chunk)
            for label, b_range in ibytes.items():

                occurance = 0
                for b in b_range:
                    occurance += cbytes[b]

                byte_ranges[label].append((float(occurance)/float(len(chunk)))*100)



    # Draw the graphs in order
    zorder=99

    fig, axEnt = plt.subplots(figsize=figsize)

    label = 'Entropy'
    c = section_colour(label)
    axEnt.plot(shannon_samples, label=label, c=c, zorder=zorder, linewidth=0.7)
    axEnt.set_xlim([0,len(shannon_samples)-1])
    axEnt.set_ylim([0, 1.1])
    axEnt.set_ylabel('Entropy')
    axEnt.set_xlabel('File (raw) offset')
    axEnt.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, pos: ('0x%x') % (int(chunksize * x))))

    # Plot the individual byte percents
    if len(ibytes) > 0:
        axBytePc = axEnt.twinx()
        axBytePc.set_ylim([0, 101])
        axBytePc.set_ylabel('Occurance of bytes (%)')
        axBytePc.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, pos: ('%i%%') % (x)))

        for label, percentages in byte_ranges.items():
            zorder -= zorder
            c = section_colour(label)
            axBytePc.plot(percentages, label=label, c=c, zorder=zorder, linewidth=0.7)


    # Filetype specific additions
    # exebin = lief.parse(filepath=filename)
    # if type(exebin) == lief.PE.Binary:

    #     # Set the virtual size axis
    #     axPEvirt = axEnt.twiny()
    #     axPEvirt.set_xlim([0,exebin.virtual_size+0x0400000])
    #     axPEvirt.set_xlabel('Base address (virtual)')
    #     axPEvirt.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, pos: ('0x%x') % (int(x+0x0400000))))


    #     # # entrypoint pointer and line
    #     ep = exebin.entrypoint
    #     ep_x = -(-ep // exebin.virtual_size)

    #     axEnt.axvline(x=exebin.virtual_size/750, linestyle='--', c=section_colour('EP'))
    #     axEnt.text(x=exebin.virtual_size/750, y=1.05, s='EP', rotation=90)


    #     for section in exebin.sections:

    #         axEnt.axvline(x=section.pointerto_raw_data/750, label=section.name, linestyle='--')
    #         axEnt.text(x=section.pointerto_raw_data/750, y=1.05, s=section.name, rotation=90)


    else:
        print('not_pe')



    # Customise the plt
    # plt.axis([0,len(shannon_samples)-1, 0,1])
    # plt.xlabel('Raw offset')
    # plt.ylabel('Entropy')

    # plt.legend(loc='center left', bbox_to_anchor=(1, 0.5))


    logo = plt.imread('cape.png')
    fig.figimage(logo, 1020, 350, alpha=.5, zorder=99)

    plt.savefig(fname=figname, format=frmt, bbox_inches='tight')


if __name__ == '__main__':

    # ## Input file
    filename='mal/aa14c8e777-cape'
    # filename='mal/test.exe'
    # filename='mal/Locky.bin.mal'
    # filename='mal/Shamoon-bin.mal'
    # filename='mal/Win32.Sofacy.A.bin.mal'
    # filename='mal/upxed.exe'
    # filename='mal/cape-9480-d746baede2c7'
    filename='mal/cape-9472-d69be688e'
    # filename='/bin/bash'



    # ## Graph formats
    fmt = 'png' # Can be svg, png...
    fsize = (12,4) # Width, Height



    # pebin = lief.parse(filepath=filename)
    # plt.figure(figsize=fsize)
    # section_ent_line(pebin, block_size=50, trend=False)
    # plt.savefig(fname='section_ent_line-50.{}'.format(fmt), format=fmt, bbox_inches='tight')



    # pebin = lief.parse(filepath=filename)
    # fig = plt.figure(figsize=fsize)
    # section_byte_occurance_histogram(pebin, fig, ncols=3, ignore_0=True, bins=1, log=0, ordered=True)
    # fig.savefig(fname='section_byte_occurance_histogram.{}'.format(fmt), format=fmt, bbox_inches='tight')



    file_ent(binname=filename)

    plt.show()
