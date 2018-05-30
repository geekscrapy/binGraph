#!/usr/bin/python

# Generate these graphs

## Pie chart of the size of the sections
# Line graph like kev has
# Heat map of sections of the pe file - looking for ent

import lief

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib import colors
from scipy.stats import entropy

from collections import Counter
import numpy as np
from math import log, e
import math
import hashlib
import statistics



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

    ## Other colour schemes

    # name_colour = int('4'+hashlib.md5(text.encode('utf-8')).hexdigest()[:4], base=16)
    # np.random.seed(int(name_colour))
    # colour = np.random.rand(3,)
    # return colour

    # name_colour = int('1'+hashlib.md5(text.encode('utf-8')).hexdigest()[:4], base=16)
    # np.random.seed(int(name_colour))
    # colour = np.random.rand(3,)
    # return colour

    # name_colour = int(hashlib.md5(text.encode('utf-8')).hexdigest()[:4], base=16)
    # np.random.seed(int(name_colour*255))
    # colour = np.random.rand(3,)
    # return colour

# Some samples may have a corrupt section name (e.g. 206c0533ce9bf83ecdf904bec2f3532d)
def fix_section_name(section, index):
        s_name = section.name
        if s_name == '' or s_name == None:
            s_name = 'unknown_'+str(index)
        return s_name

# Read files as chunks
def read_f(fh, chunksize=8192):
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


def file_ent(fh, pebin=None, chunksize=100, ibytes={'0\'s':[0], 'ascii':list(range(0,128)), 'exploit':[44,144]}, trend=False):

    shannon_samples = []
    byte_ranges = {key: [] for key in ibytes.keys()}

    prev_ent = 0
    for chunk in read_f(fh, chunksize=chunksize):

        # Calculate ent
        real_ent = shannon_ent(chunk)
        ent = statistics.median([real_ent, prev_ent])
        prev_ent = real_ent
        ent = real_ent
        shannon_samples.append(ent)


        # Calculate percentages of given bytes
        cbytes = Counter(chunk)
        for label, b_range in ibytes.items():

            occurance = 0
            for b in b_range:
                occurance += cbytes[b]

            byte_ranges[label].append(float(occurance)/float(len(chunk)))


    # Draw the graphs in order
    zorder=99

    label = 'Entropy'
    c = section_colour(label)
    plt.plot(shannon_samples, label=label, c=c, zorder=zorder, linewidth=0.7)

    for label, percentages in byte_ranges.items():
        zorder -= zorder
        c = section_colour(label)
        plt.plot(percentages, label=label, c=c, zorder=zorder, linewidth=0.7)

    # Customise the plt
    plt.axis([0,len(shannon_samples)-1, 0,1])
    # plt.title('Section Entropy (sampled @ {:d}): {}'.format(block_size, pebin.name))
    plt.xlabel('Raw offset')
    plt.ylabel('Entropy')

    plt.legend(loc='center left', bbox_to_anchor=(1, 0.5))


if __name__ == '__main__':

    # ## Input file
    filename='mal/aa14c8e777-cape'
    filename='mal/test.exe'
    filename='mal/Locky.bin.mal'
    # filename='mal/Shamoon.bin.mal'
    # filename='mal/Win32.Sofacy.A.bin.mal'
    # filename='mal/upxed.exe'
    # filename='mal/cape-9480-d746baede2c7'
    # filename='mal/cape-9472-d69be688e'




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




    fh = open(filename, "rb")
    fig = plt.figure(figsize=fsize)
    file_ent(fh=fh, chunksize=1000, trend=False)
    plt.savefig(fname='file_ent.{}'.format(fmt), format=fmt, bbox_inches='tight')

    plt.show()
