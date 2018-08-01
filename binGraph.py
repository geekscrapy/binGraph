#!/usr/bin/env python

import os
import sys
import logging
import argparse


# # Gather files to process - give it a list of paths (files or directories)
# # and it will return all files in a list
def get_files(paths, recurse):

    __files__ = []
    for f in paths:

        if recurse and os.path.isdir(f):

            for dir_name, dirs, files in os.walk(f):
                # log.debug('Found directory: {}'.format(dir_name))

                for fname in files:
                    absfile = os.path.join(dir_name, fname)

                    if os.path.isfile(absfile) and not os.path.islink(absfile) and not os.stat(absfile).st_size == 0:
                        # log.info('File found: "{}"'.format(absfile))
                        __files__.append(absfile)

        elif os.path.isfile(f) and not os.path.islink(f) and not os.stat(f).st_size == 0:
            # log.info('File exists: "{}"'.format(f))
            __files__.append(f)

        else:
            # log.critical('Not a file, skipping: "{}"'.format(f))
            pass

    return __files__


# ### Main

# Import helper functions
from graphs import common

## Statically import the graphs for now
from graphs import bin_ent, bin_hist

# # Import the defaults
parser = argparse.ArgumentParser()
parser.add_argument('-f', '--file', type=str, required=True, nargs='+', metavar='malware.exe', help='Give me a graph of this file. See - if this is the only argument specified.')
parser.add_argument('-r', '--recurse', action='store_true', help='If --file is a directory, add files recursively')
parser.add_argument('-', dest='__dummy', action='store_true', help='*** Required if --file or -f is the only argument given before a graph type is given (it\'s greedy!). E.g. "binGraph.py --file mal.exe - bin_ent"')
parser.add_argument('-p', '--prefix', type=str, help='Saved graph output filename (without extension)')
parser.add_argument('-d', '--save_dir', type=str, default=os.getcwd(), metavar='/data/graphs/', help='Where to save the graph files')
parser.add_argument('--format', type=str, default=common.__figformat__, choices=['png', 'pdf', 'ps', 'eps','svg'], required=False, metavar='png', help='Graph output format')
parser.add_argument('--figsize', type=int, nargs=2, default=common.__figsize__, metavar='#', help='Figure width and height in inches')
parser.add_argument('--dpi', type=int, default=common.__figdpi__, metavar=common.__figdpi__, help='Figure dpi')
parser.add_argument('--showplt', action='store_true', default=common.__showplt__, help='Show plot interactively (disables saving to file)')
parser.add_argument('--blob', action='store_true', default=common.__blob__, help='Do not intelligently parse certain file types. Treat all files as a binary blob. E.g. don\'t add PE entry point or section splitter to the graph')
parser.add_argument('-v', '--verbose', action='store_true', help='Print debug information to stderr')

subparsers = parser.add_subparsers(dest='graphtype', help='Graph type to generate')
subparsers.required = True

subparsers.add_parser('all')

bin_ent.args_setup(subparsers)
bin_hist.args_setup(subparsers)

args = parser.parse_args()


# # Set logging
if args.verbose:
    logging.basicConfig(stream=sys.stderr, format='Verbose | %(levelname)s | %(message)s', level=logging.DEBUG)
    logging.getLogger('matplotlib').setLevel(logging.WARNING)
else:
    logging.basicConfig(stream=sys.stderr, format='*** %(levelname)s | %(message)s', level=logging.INFO)
    # # Disable the matplotlib logger
    logging.getLogger('matplotlib').setLevel(logging.CRITICAL)

log = logging.getLogger('binGraph')

# # Verify global arguments

# # Get a list of files from the arguments
__files__ = get_files(args.file, args.recurse)

# # Is the save_dir actually a dirctory?
args.save_dir = os.path.abspath(args.save_dir)
if not os.path.isdir(args.save_dir):
    log.critical('--save_dir ("{}"), is not a directory...'.format(args.save_dir))
    exit(1)
elif not args.showplt:
    log.debug('Saving graphs to directory "{}"'.format(args.save_dir))

# # Detect if all graphs are being requested + set required defaults
graph_types = []
if args.graphtype == 'all':
    graph_types.append('bin_ent')
    graph_types.append('bin_hist')
else:
    graph_types = [args.graphtype]

# # Verify graph specific arguments
if 'bin_ent' in graph_types:
    bin_ent.args_validation(args)
if 'bin_hist' in graph_types:
    bin_hist.args_validation(args)

# # Iterate over all given files
for index, file in enumerate(__files__):

    log.info('+++ Processing: "{}"'.format(file))

    clean_fn = common.clean_fname(os.path.basename(file))

    if len(args.file) > 1 and args.prefix:
        save_fn = '{arg_prefix}-{clean_fn}-{{}}-{index}.{format}'.format(arg_prefix=args.prefix, clean_fn=clean_fn, index=index, format=args.format)
    elif len(args.file) > 1 and not args.prefix:
        save_fn = '{clean_fn}-{{}}-{index}.{format}'.format(clean_fn=clean_fn, index=index, format=args.format)

    elif len(args.file) == 1 and args.prefix:
        save_fn = '{arg_prefix}-{{}}.{format}'.format(arg_prefix=args.prefix, format=args.format)
    elif len(args.file) == 1 and args.prefix and len(graph_types) > 1:
        save_fn = '{arg_prefix}-{{}}.{format}'.format(arg_prefix=args.prefix, format=args.format)
    elif len(args.file) == 1 and not args.prefix:
        save_fn = '{clean_fn}-{{}}.{format}'.format(clean_fn=clean_fn, format=args.format)

    save_fn = os.path.join(args.save_dir, save_fn)

    if 'bin_ent' in graph_types:
        __save_fn__ = save_fn.format('bin_ent')
        log.info('+ Generating bin_ent from "{}"'.format(file))
        bin_ent.generate(binname=file, frmt=args.format, figname=__save_fn__, figsize=(args.figsize[0], args.figsize[1]), figdpi=args.dpi, chunks=args.chunks, ibytes=args.ibytes, blob=args.blob, showplt=args.showplt)

    if 'bin_hist' in graph_types:
        __save_fn__ = save_fn.format('bin_hist')
        log.info('+ Generating bin_hist from "{}"'.format(file))
        bin_hist.generate(binname=file, frmt=args.format, figname=__save_fn__, figsize=(args.figsize[0], args.figsize[1]), figdpi=args.dpi, no_zero=args.no_zero, width=args.width, g_log=args.no_log, no_order=args.no_order, showplt=args.showplt)

    log.info('+++ Complete: "{}"'.format(file))

