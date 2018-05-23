#!/usr/bin/python

# Generate these graphs

## Pie chart of the size of the sections
# Line graph like kev has
# Heat map of sections of the pe file - looking for ent

import lief

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib import colors
from scipy.interpolate import interp1d

from collections import Counter
import numpy as np
from math import log, e
import hashlib

## Helper functions
def shannon_ent(labels, base=None):
    value,counts = np.unique(labels, return_counts=True)
    norm_counts = counts / counts.sum()
    base = e if base is None else base
    return -(norm_counts * np.log(norm_counts)/np.log(base)).sum()

# Assign a colour to the section name. Static between samples
def section_colour(text):

    # hash_c = hashlib.md5(text.encode('utf-8')).hexdigest().upper()
    # color = 'F'+hash_c[:1]+'F'+hash_c[2:3]+'F'+hash_c[4:5]

    # print(color)

    # name_colour = int(color, base=16)/8
    # np.random.seed(int(name_colour))
    # colour = np.random.rand(3,)
    # return colour


    name_colour = int('F'+hashlib.md5(text.encode('utf-8')).hexdigest()[:4], base=16)
    np.random.seed(int(name_colour))
    colour = np.random.rand(3,)
    return colour

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
def fix_section_name(section):
        s_name = section.name
        if s_name == '' or s_name == None:
            s_name = 'unknown_'+str(i)
        return s_name

## Occurance per byte
# def section_byte_occurance_heatmap(pebin):
#     z = []
#     y = []
#     for section in pebin.sections:
#         row = []
#         c = Counter(section.content)
#         for i in range(0, 256):
#             row.append(c[i])
#         z.append(row)
#         y.append(section.name)

#     data = go.Heatmap(
#         x=['x{:02}'.format(d) for d in range(0, 256)],
#         y=y,
#         z=z,
#         colorscale='Viridis',
#     )

#     layout = go.Layout(
#         title='Byte frequency: {}'.format(filename),
#         xaxis=dict(
#             title='Byte: x0 to xFF',
#             ticktext=['x{:02}'.format(d) for d in range(0, 256, 5)],
#             tickvals=list(range(0, 256, 5)),
#             tickangle=45,
#         ),
#         yaxis=dict(
#             title='Binary section',
#             ticktext=[ s.name for s in pebin.sections ],
#             tickvals=[ s.name for s in pebin.sections ]
#         )
#     )

#     return [data], layout

# ## Section size bar chart
# def section_size_bar(pebin):

#     section_size_bar_raw = go.Bar(
#         name='Raw size',
#         x=[section.name for section in pebin.sections],
#         y=[section.size for section in pebin.sections]
#     )

#     section_size_bar_virtual = go.Bar(
#         name='Virtual size',
#         x=[section.name for section in pebin.sections],
#         y=[section.virtual_size for section in pebin.sections]
#     )

#     data = [section_size_bar_raw, section_size_bar_virtual]

#     layout = go.Layout(
#         barmode='stack',
#         title='Raw/virtual section sizes: {}'.format(filename),
#         xaxis=dict(
#             title='Sections',
#             zeroline=False
#         ),
#         yaxis=dict(
#             title='Size',
#             ticklen=5,
#             nticks=10,
#             zeroline=False,
#             type='log',
#             autorange=True
#         )
#     )

#     return data, layout


## Histogram per byte - sorted
def section_byte_occurance_histogram_sorted(pebin, filename='section_byte_occurance_histogram_sorted.png', figsize=(10,7), ncols=2, sorted=True, ignore_null=True, bins=1, log=1):

    fig = plt.figure(figsize=figsize)
    ignore_null = int(ignore_null)

    for i, section in enumerate(pebin.sections):

        s_name = fix_section_name(section)
        s_colour = section_colour(s_name)

        row = []
        c = Counter(section.content)
        for x in range(ignore_null, 256):
            row.append(c[x])




        b = list(zip(list(range(0,256)),row))
        print(b)




        ax = fig.add_subplot(-(-len(pebin.sections) // ncols),ncols,i+1)
        ax.bar((range(ignore_null,256)), row, bins, color=s_colour, log=log)

        ax.set_xlabel(s_name)

        # ax.set_title(s_name, fontsize='large')
        ax.set_xticks([])
        ax.set_xlim([0, 255])

    fig.suptitle('Byte histogram, per section: {}'.format(pebin.name))
    fig.subplots_adjust(hspace=0.5)
    fig.savefig('section_byte_occurance_histogram.png')


## Histogram per byte
def section_byte_occurance_histogram(pebin, filename='section_byte_occurance_histogram.png', figsize=(10,7), ncols=2, sorted=True, ignore_null=True, bins=1, log=1):

    fig = plt.figure(figsize=figsize)
    ignore_null = int(ignore_null)

    for i, section in enumerate(pebin.sections):

        s_name = fix_section_name(section)
        s_colour = section_colour(s_name)

        row = []
        c = Counter(section.content)
        for x in range(ignore_null, 256):
            row.append(c[x])

        ax = fig.add_subplot(-(-len(pebin.sections) // ncols),ncols,i+1)
        ax.bar((range(ignore_null,256)), row, bins, color=s_colour, log=log)

        ax.set_xlabel(s_name)

        # ax.set_title(s_name, fontsize='large')
        ax.set_xticks([])
        ax.set_xlim([0, 255])

    fig.suptitle('Byte histogram, per section: {}'.format(pebin.name))
    fig.subplots_adjust(hspace=0.5)
    fig.savefig('section_byte_occurance_histogram.png')


## Ent per section
## blocksize int:   content is divided into blocks, each block is sampled for shannon entropy. More blocks, greater resolution
## trend bool/None: Show a trend line. True: Show trend line, False: Dont show trend line, None: Show ONLY the trend line
def section_ent_line(pebin, filename='section_ent_line.png', figsize=(10,7), block_size=75, trend=False):

    fig = plt.figure(figsize=figsize)

    data = []
    for i, section in enumerate(pebin.sections):

        s_name = fix_section_name(section)

        # Get a per section colour that is unique across all samples. e.g. same section name = same colour
        s_colour = section_colour(s_name)

        # This gets the content block amounts and rounds up - so we always get 1 more than required
        block_len = -(-len(section.content) // block_size)

        shannon_samples = []

        i = 1
        prev_end = 0
        while prev_end <= len(section.content):

            block_start = prev_end
            block_end = i * block_len

            ent = shannon_ent(section.content[ block_start : block_end ])
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

            plt.plot(x_new,y_new, label=s_name, c=s_colour)

        if not trend == None:
            plt.plot(shannon_samples, label=s_name, c=s_colour)

        # Customise the plt
        plt.axis([0,len(shannon_samples), 0,9])
        plt.title('Section Entropy (sampled @ {:d}): {}'.format(block_size, pebin.name))
        plt.xlabel('Sample block')
        plt.ylabel('Entropy')
        plt.legend()

    fig.savefig('section_ent_line.png')

if __name__ == '__main__':

    # filename='mal/aa14c8e777-cape'
    # filename='mal/test.exe'
    # filename='mal/Locky.bin.mal'
    # filename='mal/Shamoon.bin.mal'
    filename='mal/Win32.Sofacy.A.bin.mal'
    # filename='upx.exe'

    pebin = lief.PE.parse(filename=filename)

    # section_ent_line(pebin, block_size=75, trend=False)
    section_byte_occurance_histogram_sorted(pebin)

   


