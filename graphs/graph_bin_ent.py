"""

## Entropy and byte occurrence analysis over all file
-------------------------------------------
binname:    File to load and analyse
figsize:    Specify size of the figure ouputted
frmt:       Output filetype. Can be anything supported by matplotlib - png, svg, jpg
figname:    Filename to save graph
figsize:    Size to save figure, (width,height)
showplt:   Show the graph interactively, disables saving to a file

chunks int:             How many chunks to split the file over. Smaller chunks give a more averaged graph, a larger number of chunks give more detail
ibytes dicts of lists:  A dict of interesting bytes wanting to be displayed on the graph. These can often show relationships and reason for dips or
                         increases in entropy at particular points. Bytes within each type are defined as lists of _decimals_, _not_ hex.

"""

# # Get helper functions
from graphs.helpers import shannon_ent
# # Get common graph defaults
from graphs.global_defaults import __figformat__, __figsize__, __figdpi__, __showplt__, __blob__, __pyver__

# # Import graph specific libs
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from matplotlib.ticker import MaxNLocator

import hashlib
import numpy as np
import statistics
from collections import Counter
import os
import json

# # https://www.peterbe.com/plog/jsondecodeerror-in-requests.get.json-python-2-and-3
import json
try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError

import lief

import logging
log = logging.getLogger()


# # Graph defaults
__chunks__ = 750
__ibytes__= '{"0\'s": [0], "Printable ASCII": [32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126], "Exploit": [44, 144]}'
__ibytes_dict__ = json.loads(__ibytes__)

# Set args in args parse
def args_setup(arg_parser):

    parser_bin_ent = arg_parser.add_parser('bin_ent')
    parser_bin_ent.add_argument('-c','--chunks', type=int, default=__chunks__, metavar='750', help='Defines how many chunks the binary is split into (and therefore the amount of bytes submitted for shannon sampling per time). Higher number gives more detail')
    parser_bin_ent.add_argument('--ibytes', type=str, nargs='?', default=__ibytes__, metavar='\"{\\\"0\'s\\\": [0] , \\\"Exploit\\\": [44, 144] }\"', help='JSON of bytes to include in the graph. To disable this option, either set the flag without an argument, or set value to "{}"')

# Validate graph specific arguments - Set the defaults here
class ArgValidationEx(Exception): pass
def args_validation(args):

    # # Test to see if we should use defaults
    if args.graphtype == 'all':
        args.ibytes = __ibytes__
        args.chunks = __chunks__ 

    # # Test ibytes are sane
    if args.ibytes == None:
        args.ibytes = json.loads('{}')
    else:
        try:
            args.ibytes = json.loads(args.ibytes)
        except JSONDecodeError as e:
            raise ArgValidationEx('Error decoding --ibytes value. {}: "{}"'.format(e, args.ibytes))

# Generate the graph
def generate(binname, frmt=__figformat__, figname=None, figsize=__figsize__, figdpi=__figdpi__, blob=__blob__, showplt=__showplt__, chunks=750, ibytes=__ibytes_dict__):

    if not figname:
        figname = 'bin_ent-{}.{}'.format(clean_fname(binname), frmt)
        log.debug('No name given. Generated: {}'.format(figname))

    with open(binname, 'rb') as fh:
        log.debug('Opening: "{}"'.format(binname))

        # # Calculate the overall chunksize 
        fs = os.fstat(fh.fileno()).st_size
        if chunks > fs:
            chunksize = 1
            nr_chunksize = 1
        else:
            chunksize = -(-fs // chunks)
            nr_chunksize = fs / chunks

        log.debug('Filesize: {}, Chunksize (rounded): {}, Chunksize: {}, Chunks: {}'.format(fs, chunksize, nr_chunksize, chunks))

        # # Create byte occurrence dict if required
        if len(ibytes) > 0:
            byte_ranges = {key: [] for key in ibytes.keys()}

        log.debug('Going for iteration over bytes with chunksize {}'.format(chunksize))

        shannon_samples = []
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

                    occurrence = 0
                    for b in b_range:
                        occurrence += cbytes[b]

                    byte_ranges[label].append((float(occurrence)/float(len(chunk)))*100)

    log.debug('Closed: "{}"'.format(binname))

    # # Create the figure
    fig, host = plt.subplots(figsize=figsize, dpi=figdpi)

    log.debug('Plotting shannon samples')
    host.plot(np.array(shannon_samples), label='Entropy', c=section_colour('Entropy'), zorder=1001, linewidth=1)

    host.set_ylabel('Entropy\n'.format(chunksize))
    host.set_xlabel('Raw file offset')
    host.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, pos: ('0x{:02X}'.format(int(x * nr_chunksize)))))
    host.xaxis.set_major_locator(MaxNLocator(10))
    plt.xticks(rotation=-10, ha='left')

    # # Draw the graphs in order
    zorder=1000

    # # Plot individual byte percentages
    if len(ibytes) > 0:
        log.debug('Using ibytes: {}'.format(ibytes))

        axBytePc = host.twinx()
        axBytePc.set_ylabel('Occurrence of "interesting" bytes')
        axBytePc.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, pos: ('{:d}%'.format(int(x)))))

        for label, percentages in byte_ranges.items():
            zorder -= 1
            c = section_colour(label)
            axBytePc.plot(np.array(percentages), label=label, c=c, zorder=zorder, linewidth=0.7, alpha=0.75)

        axBytePc.set_ybound(lower=-0.3, upper=101)


    # # Amount of space required between the title and graph elements (such as the section name)
    # # Append a \n if you need more space!
    title_gap = '\n'

    # # Filetype specific additions
    if blob:
        log.warning('Parsing file as blob - no filetype specific features')
    else:

        try:
            exebin = lief.parse(filepath=binname)
            log.debug('Parsed with lief as {}'.format(exebin.format))

        except Exception as e:
            exebin = None
            log.warning('Failed to parse with lief: {}'.format(e))

        if exebin:
            if type(exebin) == lief.PE.Binary:

                log.debug('Adding PE customisations')

                # # Entrypoint (EP) pointer and vline
                v_ep = exebin.va_to_offset(exebin.entrypoint) / nr_chunksize
                host.axvline(x=v_ep, linestyle=':', c='r', zorder=zorder-1)
                host.text(x=v_ep, y=1.07, s='EP', rotation=45, va='bottom', ha='left')

                longest_section_name = 0

                # # Section vlines
                for index, section in enumerate(exebin.sections):
                    zorder -= 1

                    section_name = safe_section_name(section.name, index)
                    section_offset = section.offset / nr_chunksize

                    log.debug('{}: {}'.format(section_name, section.offset))

                    host.axvline(x=section_offset, linestyle='--', zorder=zorder)
                    host.text(x=section_offset, y=1.07, s=section_name, rotation=45, va='bottom', ha='left')

                    # # Get longest section name
                    longest_section_name = len(section_name) if len(section_name) > longest_section_name else longest_section_name

                # # Eval the space required to show the section names
                title_gap = int(longest_section_name / 4) * '\n'
                
            else:
                log.debug('Not currently customised: {}'.format(exebin.format))

    # # Plot the entropy graph
    host.set_xbound(lower=-0.5, upper=len(shannon_samples)+0.5)
    host.set_ybound(lower=0, upper=1.05)

    # # Add legends + title (adjust for different options given)
    legends = []
    if len(ibytes) > 0:
        legends.append(host.legend(loc='upper left', bbox_to_anchor=(1.1, 1), frameon=False))
        legends.append(axBytePc.legend(loc='upper left', bbox_to_anchor=(1.1, 0.85), frameon=False))
    else:
        legends.append(host.legend(loc='upper left', bbox_to_anchor=(1.01, 1), frameon=False))

    # # Check section name length

    if blob:
        host.set_title('Binary entropy (sampled over {chunksize} byte chunks): {binname}{title_gap}'.format(chunksize=chunksize, binname=os.path.basename(binname), title_gap=title_gap))
    else:
        host.set_title('Binary entropy (sampled over {chunksize} byte chunks): {binname}{title_gap}'.format(chunksize=chunksize, binname=os.path.basename(binname), title_gap=title_gap))

    # Add watermark
    add_watermark(fig)

    plt.tight_layout()

    if showplt:
        log.debug('Opening graph interactively')
        plt.show()
    else:
        plt.savefig(figname, format=frmt, dpi=figdpi, bbox_inches='tight',  bbox_extra_artists=tuple(legends))
        log.debug('Saved to: "{}"'.format(figname))

    plt.clf()
    plt.cla()
    plt.close()


# # Read files as chunks
def get_chunk(fh, chunksize=8192):
    while True:
        chunk = fh.read(chunksize)

        # # Convert to bytearray if not python 3
        if __pyver__ <= 3:
            chunk = bytearray(chunk)

        if chunk:
            yield list(chunk)
        else:
            break

# # Some samples may have a corrupt section name (e.g. 206c0533ce9bf83ecdf904bec2f3532d)
def safe_section_name(s_name, index):
        if s_name == '' or s_name == None:
            s_name = 'sect_{:d}'.format(str(index))
        return s_name

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