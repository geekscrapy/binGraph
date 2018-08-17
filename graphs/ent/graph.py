"""
Entropy and byte occurrence analysis over all file
-------------------------------------------
abs_fpath str:          Absolute file path - File to load and analyse
fname str:              Filename
blob bool:              Do not intelligently parse certain file types. Treat all files as a binary blob. E.g. don\'t add PE entry point or section splitter to the graph

chunks int:             How many chunks to split the file over. Smaller chunks give a more averaged graph, a larger number of chunks give more detail
ibytes dicts of lists:  A dict of interesting bytes wanting to be displayed on the graph. These can often show relationships and reason for dips or
                        increases in entropy at particular points. Bytes within each type are defined as lists of _decimals_, _not_ hex.
lib str lief or pefile: Which library to use to parse file specific features
"""
from __future__ import division

# # Import graph specific libs
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from matplotlib.ticker import MaxNLocator

import hashlib
import numpy as np
import statistics
from collections import Counter
import os
import json
import sys

# # Try lief first, it reads more formats
try:
    import lief
except ImportError as e1:
    try:
        import pefile
    except ImportError as e2:
        pass


# # Python 2/3 fix
import json
try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError

import logging
log = logging.getLogger('graph.ent')

# # Graph defaults
__chunks__ = 750
__ibytes__= '{"0\'s": [0], "Printable ASCII": [32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126], "Exploit": [44, 144]}'
__ibytes_dict__ = json.loads(__ibytes__)

# # Set args in args parse - the given parser is a sub parser
def args_setup(arg_parser):
    arg_parser.add_argument('-c','--chunks', type=int, default=__chunks__, metavar='750', help='Defines how many chunks the binary is split into (and therefore the amount of bytes submitted for shannon sampling per time). Higher number gives more detail')
    arg_parser.add_argument('--ibytes', type=str, nargs='?', default=__ibytes__, metavar='\"{\\\"0\'s\\\": [0] , \\\"Exploit\\\": [44, 144] }\"', help='JSON of bytes to include in the graph. To disable this option, either set the flag without an argument, or set value to "{}"')

# # Validate graph specific arguments - Set the defaults here
class ArgValidationEx(Exception): pass
def args_validation(args):

    # # Test to see what matplotlib backend is setup
    backend = matplotlib.get_backend()
    if not backend == 'TkAgg':
        log.warning('{} matplotlib backend in use. This graph generation was tested with "TkAgg", bugs may lie ahead...'.format(backend))
    else:
        log.debug('Matplotlib backend: {}'.format(backend))

    # # Test to see if we should use defaults
    if args.graphtype == 'all':
        args.ibytes = __ibytes__
        args.chunks = __chunks__ 

    # # Test ibytes is jalid json
    if args.ibytes == None:
        args.ibytes = json.loads('{}')
    else:
        try:
            args.ibytes = json.loads(args.ibytes)
        except JSONDecodeError as e:
            raise ArgValidationEx('Error decoding json --ibytes value. {}: "{}"'.format(e, args.ibytes))

    # # Test to see if ibytes are sane
    for name, bytelist in args.ibytes.items():

        if not (type(name) == str or type(bytelist) == list) or not len(bytelist) > 0:
            raise ArgValidationEx('Error validating --ibytes. Name is not a string or bytes not list: {} = {}'.format(name, bytelist))

        for b in bytelist:
            if not type(b) == int:
                raise ArgValidationEx('Error validating --ibytes. Item in list not an int: {} = {}'.format(name, b))

# # Generate the graph
def generate(abs_fpath, fname, blob, chunks=__chunks__, ibytes=__ibytes_dict__, **kwargs):

    with open(abs_fpath, 'rb') as fh:
        log.debug('Opening: "{}"'.format(fname))

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

        log.debug('Producing shannon ent with chunksize {}'.format(chunksize))

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

    log.debug('Closed: "{}"'.format(fname))

    # # Create the figure
    fig, host = plt.subplots()

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
    if not blob:

        bp = bin_proxy(abs_fpath)

        if None in (bp.bin, bp.type):
            log.warning('Failed to parse binary format, parsing like --blob')

        else:

            if bp.type == 'PE':

                log.debug('Adding PE customisations')

                # # Entrypoint (EP) pointer and vline
                phy_ep_pointer = bp.get_physical_from_rva(bp.get_virtual_ep()) / nr_chunksize
                log.debug('{}: {}'.format('Entrypoint', hex(bp.get_virtual_ep())))

                host.axvline(x=phy_ep_pointer, linestyle=':', c='r', zorder=zorder-1)
                host.text(x=phy_ep_pointer, y=1.07, s='EP', rotation=45, va='bottom', ha='left')

                longest_section_name = 0

                # # Section vlines
                for index, section in bp.sections():
                    zorder -= 1

                    section_name = safe_section_name(section.name, index)
                    section_offset = section.offset / nr_chunksize

                    log.debug('{}: {}'.format(section_name, hex(section.offset)))

                    host.axvline(x=section_offset, linestyle='--', zorder=zorder)
                    host.text(x=section_offset, y=1.07, s=section_name, rotation=45, va='bottom', ha='left')

                    # # Get longest section name
                    longest_section_name = len(section_name) if len(section_name) > longest_section_name else longest_section_name

                # # Eval the space required to show the section names
                title_gap = int(longest_section_name / 3) * '\n'
                
            else:
                log.debug('Not currently customised: {}'.format(bp.type))

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

    if blob:
        host.set_title('Binary entropy (sampled over {chunksize} byte chunks): {fname}{title_gap}'.format(chunksize=chunksize, fname=fname, title_gap=title_gap))
    else:
        host.set_title('Binary entropy (sampled over {chunksize} byte chunks): {fname}{title_gap}'.format(chunksize=chunksize, fname=fname, title_gap=title_gap))

    # # Return the plt and kwargs for the plt.savefig function
    return (plt, {'bbox_inches':'tight',  'bbox_extra_artists':tuple(legends)})

# ### Helper functions

# # Abstracts the bin properties away from specific library calls enabling lief and pefile usage
class bin_proxy(object):
    """Abstract for different binary parsers types in use"""
    def __init__(self, abs_fpath, lib=None):
        super(bin_proxy, self).__init__()
        self.abs_fpath = abs_fpath

        if lib:
            self.lib = lib
        else:

            if 'lief' in sys.modules:
                self.lib = 'lief'
            elif 'pefile' in sys.modules:
                self.lib = 'pefile'
            else:
                # # We dont have a parser
                return None, None

        self.bin, self.type = None, None
        self.__parse_bin()

    class __ParseError(Exception):

        pass

    def __parse_bin(self):

        if self.lib == 'lief':
            try:
                self.bin = lief.parse(filepath=self.abs_fpath)
                if type(self.bin) == lief.PE.Binary:
                    self.type = 'PE'
                    log.debug('Parsed with lief as: {}'.format(self.type))
                else:
                    self.bin = None
                    log.debug('File is a currently unsupported format'.format(self.type))

            except lief.bad_file as e:
                log.warning('Failed to parse with lief: {}'.format(e))

        elif self.lib == 'pefile':
            try:
                self.bin = pefile.PE(self.abs_fpath)
                self.type = 'PE'

                log.debug('Parsed with pefile as: {}'.format(self.type))

            except pefile.PEFormatError as e:
                log.warning('Failed to parse with pefile: {}'.format(e))

    def get_virtual_ep(self):

        if self.lib == 'lief':
            return self.bin.optional_header.addressof_entrypoint
        elif self.lib == 'pefile':
            return self.bin.OPTIONAL_HEADER.AddressOfEntryPoint

    def get_physical_from_rva(self, rva):

        if self.lib == 'lief':
            return self.bin.rva_to_offset(rva)
        elif self.lib == 'pefile':
            return self.bin.get_physical_by_rva(rva)

    def sections(self):

        index = 0
        sections = []

        for lib_section in self.bin.sections:

            section = section_proxy(self.lib, lib_section)

            yield index, section
            index += 1
# # Part of bin_proxy - abstracts section calls
class section_proxy(object):
    """Abstract for different binary parsers types in use"""
    def __init__(self, lib, lib_section):
        super(section_proxy, self).__init__()
        self.lib = lib
        self.lib_section = lib_section

        if self.lib == 'lief':
            self.name = lib_section.name
            self.offset = lib_section.offset
        elif self.lib == 'pefile':
            self.name = str(lib_section.Name.rstrip(b'\x00').decode("utf-8"))
            self.offset = self.lib_section.get_offset_from_rva(self.lib_section.VirtualAddress)

# # Read files as chunks
def get_chunk(fh, chunksize=8192):
    while True:
        chunk = fh.read(chunksize)

        # # Convert to bytearray if not python 3
        if sys.version_info[0] <= 3:
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

# # Calculate entropy given a list
def shannon_ent(labels, base=256):
    value, counts = np.unique(labels, return_counts=True)
    norm_counts = counts / counts.sum()
    base = e if base is None else base
    return -(norm_counts * np.log(norm_counts)/np.log(base)).sum()



if __name__ == '__main__':

    import argparse

    logging.basicConfig(stream=sys.stderr, format='%(levelname)s | %(message)s', level=logging.DEBUG)
    logging.getLogger('matplotlib').setLevel(logging.CRITICAL)
    log = logging.getLogger('ent')

    # ## Global graphing default values
    __figformat__ = 'png'   # Output format of saved figure
    __figsize__ = (12,4)    # Size of figure in inches
    __figdpi__ = 100        # DPI of figure
    __showplt__ = False     # Show the plot interactively
    __blob__ = False        # Treat all files as binary blobs. Disable intelligently parsing of file format specific features.

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', type=str, required=True, metavar='malware.exe', help='Give me a graph of this file. See - if this is the only argument specified.')
    parser.add_argument('--showplt', action='store_true', default=__showplt__, help='Show plot interactively (disables saving to file)')
    parser.add_argument('--format', type=str, default=__figformat__, choices=['png', 'pdf', 'ps', 'eps','svg'], required=False, metavar='png', help='Graph output format')
    parser.add_argument('--figsize', type=int, nargs=2, default=__figsize__, metavar='#', help='Figure width and height in inches')
    parser.add_argument('--dpi', type=int, default=__figdpi__, metavar=__figdpi__, help='Figure dpi')
    parser.add_argument('--blob', action='store_true', default=__blob__, help='Do not intelligently parse certain file types. Treat all files as a binary blob. E.g. don\'t add PE entry point or section splitter to the graph')

    args_setup(parser)

    args = parser.parse_args()

    args.graphtype = __name__

    args_validation(args)

    args_dict = args.__dict__
    args_dict['abs_fpath'] = args.file
    args_dict['fname'] = os.path.basename(args.file)
    args_dict['abs_save_fpath'] = '{}.{}'.format(os.path.basename(args_dict['abs_fpath']), args.format)

    plt, save_kwargs = generate(**args_dict)

    fig = plt.gcf()
    fig.set_size_inches(*args.figsize, forward=True)

    ax = plt.gca()
    ax.text(-0.03, -0.15, 'github.com/geekscrapy/binGraph', ha='left', va='top', family='monospace', transform=ax.transAxes)

    plt.tight_layout()

    if args.showplt:
        log.debug('Opening graph interactively')
        plt.show()
    else:
        plt.savefig(args_dict['abs_save_fpath'], format=args.format, dpi=args.dpi, forward=True, **save_kwargs)
        log.info('Graph saved to: "{}"'.format(args_dict['abs_save_fpath']))
