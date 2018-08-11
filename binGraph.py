#!/usr/bin/env python

import sys
import pkgutil
import os
import logging
import argparse

#### Helper functions

# # Gather files to process - give it a list of paths (files or directories)
# # and it will return all files in a list
def find_files(search_paths, recurse):

    __files__ = []
    for f in search_paths:

        if recurse and os.path.isdir(f):

            for dir_name, dirs, files in os.walk(f):
                log.debug('Found directory: {}'.format(dir_name))

                for fname in files:
                    abs_fpath = os.path.join(dir_name, fname)

                    if os.path.isfile(abs_fpath) and not os.path.islink(abs_fpath) and not os.stat(abs_fpath).st_size == 0:
                        log.info('File found: "{}"'.format(abs_fpath))
                        __files__.append(abs_fpath)

        elif os.path.isfile(f) and not os.path.islink(f) and not os.stat(f).st_size == 0:
            abs_fpath = os.path.abspath(f)
            log.info('File exists: "{}"'.format(abs_fpath))
            __files__.append(abs_fpath)

        else:
            log.critical('Not a file, skipping: "{}"'.format(f))
            pass

    return __files__

# # Cleanup given filename
def clean_fname(fn):

    return ''.join([c for c in fn if c.isalnum()])

# # Generate the different file names required
def gen_names(ffrmt, abs_fpath, abs_save_path, save_prefix=None, graphtype=None, findex=None):

    base_save_fname = '{prefix}-{graphtype}-{cleaned_fname}-{findex}.{ffrmt}'

    if save_prefix:
        save_fname = base_save_fname.replace('{prefix}', save_prefix)
    else:
        save_fname = base_save_fname.replace('{prefix}-', '')

    if graphtype:
        save_fname = save_fname.replace('{graphtype}', graphtype)
    else:
        save_fname = save_fname.replace('{graphtype}-', '')

    cleaned_fname = clean_fname(os.path.basename(abs_fpath))
    if type(findex) == int:
        save_fname = save_fname.replace('{cleaned_fname}', cleaned_fname)
        save_fname = save_fname.replace('{findex}', str(findex))
    else:
        save_fname = save_fname.replace('{cleaned_fname}-{findex}', cleaned_fname)

    save_fname = save_fname.replace('{ffrmt}', ffrmt)

    abs_save_fpath = os.path.join(abs_save_path, save_fname)

    return abs_save_fpath, os.path.basename(abs_fpath), cleaned_fname

# # Add watermark
def add_watermark(fig):
    credit = plt.imread(os.path.dirname(os.path.realpath(__file__))+'/credit.png')
    fig.figimage(credit, alpha=.5, zorder=99)

# # Import graphtypes
def get_graph_modules(dirname):

    modules = {}
    for importer, package_name, _ in pkgutil.iter_modules([dirname]):
        full_package_name = '{}.{}'.format(dirname, package_name)

        if ('graph_' in full_package_name) and not (full_package_name in sys.modules):
            module = importer.find_module(package_name)

            if sys.version_info[0] < 3:
                module = module.load_module(full_package_name)
            else:
                module = module.load_module()

            modules[package_name.replace('graph_', '')] = module

    return modules


# ### Main

# # Import default values functions
from graphs import global_defaults as defaults

# # Try and import the graphs
try:
    graphs = get_graph_modules('graphs')
except Exception as e:
    log.critical('Failed to import graph: {}'.format(e))
    exit(0)

# # Import the defaults
parser = argparse.ArgumentParser()
parser.add_argument('-f', '--file', type=str, required=True, nargs='+', metavar='malware.exe', help='Give me a graph of this file. See - if this is the only argument specified.')
parser.add_argument('-r', '--recurse', action='store_true', help='If --file is a directory, add files recursively')
parser.add_argument('-', dest='__dummy', action='store_true', help='*** Required if --file or -f is the only argument given before a graph type is provided (it\'s greedy!). E.g. "binGraph.py --file mal.exe - bin_ent"')
parser.add_argument('-p', '--prefix', type=str, help='Saved graph output filename (without extension)')
parser.add_argument('-o', '--out', type=str, dest='save_dir', default=os.getcwd(), metavar='/data/graphs/', help='Where to save the graph files')
parser.add_argument('--showplt', action='store_true', default=defaults.__showplt__, help='Show plot interactively (disables saving to file)')
parser.add_argument('--format', type=str, default=defaults.__figformat__, choices=['png', 'pdf', 'ps', 'eps','svg'], required=False, metavar='png', help='Graph output format')
parser.add_argument('--figsize', type=int, nargs=2, default=defaults.__figsize__, metavar='#', help='Figure width and height in inches')
parser.add_argument('--dpi', type=int, default=defaults.__figdpi__, metavar=defaults.__figdpi__, help='Figure dpi')
parser.add_argument('--blob', action='store_true', default=defaults.__blob__, help='Do not intelligently parse certain file types. Treat all files as a binary blob. E.g. don\'t add PE entry point or section splitter to the graph')
parser.add_argument('-v', '--verbose', action='store_true', help='Print debug information to stderr')

subparsers = parser.add_subparsers(dest='graphtype', help='Graph type to generate')
subparsers.required = True

subparsers.add_parser('all')

# # Loop over all graph types to add their graph specific options
for name, module in graphs.items():
    module.args_setup(subparsers)

args = parser.parse_args()


# # Set logging
if args.verbose:
    logging.basicConfig(stream=sys.stderr, format='Verbose | %(levelname)s | %(message)s', level=logging.DEBUG)
    logging.getLogger('matplotlib').setLevel(logging.WARNING)
else:
    logging.basicConfig(stream=sys.stderr, format='*** %(levelname)s | %(message)s', level=logging.INFO)
    # # Lower the matplotlib logger
    logging.getLogger('matplotlib').setLevel(logging.CRITICAL)

log = logging.getLogger('binGraph')

log.debug('Found the following graph types: {}'.format(', '.join(graphs.keys())))

# # Verify global arguments

# # Get a list of files from the arguments
__files__ = find_files(args.file, args.recurse)
# # Adjust args to retain the list of files
args.files = __files__

# # Is the save_dir actually a dirctory?
args.save_dir = os.path.abspath(args.save_dir)
if not os.path.isdir(args.save_dir):
    log.critical('--save_dir is not a directory: {}'.format(args.save_dir))
    exit(1)

# # Detect if all graphs are being requested + set required defaults
__graphtypes__ = []
if args.graphtype == 'all':
    __graphtypes__ = graphs
else:
    __graphtypes__ = { args.graphtype: graphs[args.graphtype] }

log.debug('Generating graphs: {}'.format(', '.join(__graphtypes__.keys()) ))

# # Allow graph modules to verify if their arguments have been set correctly
for name, module in __graphtypes__.items():
    try:
        module.args_validation(args)
    except Exception as e:
        log.critical(e)
        exit(0)

# # Iterate over all given files
for index, abs_fpath in enumerate(__files__):

    log.info('+++ Processing: "{}"'.format(abs_fpath))
    args_dict = args.__dict__

    for module_name, module in __graphtypes__.items():
        abs_save_fpath, fname, clean_fname = gen_names(args.format, abs_fpath, args.save_dir, save_prefix=args.prefix, graphtype=module_name, findex=(index if len(__graphtypes__)<1 else None))

        args_dict['abs_fpath'] = abs_fpath # Define the current file we are acting on
        args_dict['fname'] = fname
        args_dict['clean_fname'] = clean_fname

        # # Generate and output the graph
        plt, save_kwargs = module.generate(**args_dict)

        fig = plt.gcf()
        fig.set_size_inches(*args.figsize, forward=True)

        add_watermark(fig)

        plt.tight_layout()


        if args.showplt:
            log.debug('Opening graph interactively')
            plt.show()
        else:
            plt.savefig(abs_save_fpath, format=args.format, dpi=args.dpi, forward=True, **save_kwargs)
            log.info('Graph saved to: "{}"'.format(abs_save_fpath))

        plt.clf()
        plt.cla()
        plt.close()

    log.info('+++ Complete: "{}"'.format(abs_fpath))
