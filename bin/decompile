#!/usr/bin/env python3

# BSD 3-Clause License
#
# Copyright (c) 2016, 2017, The University of Sydney. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Standard lib imports
import argparse
import logging
import sys
from os.path import abspath, dirname, join

# Prepend .. to $PATH so the project modules can be imported below
src_path = join(dirname(abspath(__file__)), "..")
sys.path.insert(0, src_path)

# Local project imports
import src.exporter as exporter
import src.dataflow as dataflow
import src.tac_cfg as tac_cfg
import src.settings as settings

# Version string to display with -v
VERSION = """\
+------------------------------+
| Vandal EVM Decompiler v0.0.3 |
| (c) The University of Sydney |
+------------------------------+\
"""


# Define a version() function in case we want dynamic version strings later
def version():
    return VERSION


# Configure argparse
parser = argparse.ArgumentParser(
    description="An EVM bytecode disassembly decompiler that generates "
                "three-address code for program analysis. Use config.ini "
                "to set further configuration options.")

parser.add_argument("-a",
                    "--disassembly",
                    action="store_true",
                    default=False,
                    help="decompile dissassembled input. Overrides '-b'.")

parser.add_argument("-b",
                    "--bytecode",
                    action="store_true",
                    default=False,
                    help="disassemble and decompile bytecode input. This is "
                         "the default mode.")

parser.add_argument("-g",
                    "--graph",
                    nargs="?",
                    const="cfg.html",
                    metavar="FILE",
                    default=None,
                    help="generate a visual representation of basic block "
                         "relationships with the format inferred from the "
                         "given output filename (cfg.dot by default). "
                         "Non-DOT formats like pdf, png, etc. require "
                         "Graphviz to be installed. Use html to generate "
                         "an interactive web page of the graph.")

parser.add_argument("-t",
                    "--tsv",
                    nargs="?",
                    const="",
                    metavar="DIR",
                    default=None,
                    help="generate tab-separated .facts files for Souffle "
                         "and write files to the specified directory, which "
                         "will be recursively created if it does not exist "
                         "(current working directory by default).")

parser.add_argument("-d",
                    "--dominators",
                    action="store_true",
                    default=False,
                    help="If producing tsv output, also include graph "
                         "dominator relations.")

parser.add_argument("-o",
                    "--opcodes",
                    nargs="*",
                    default=[],
                    metavar="OPCODE",
                    help="If producing tsv output, also include relations "
                         "encoding all occurrences of the specified "
                         "list of opcodes. Opcode X will be stored in "
                         "op_X.facts.")

parser.add_argument("-c",
                    "--config",
                    metavar="CFG_STRING",
                    help="override settings from the configuration files "
                         "in the format \"key1=value1, key2=value2...\" "
                         "(with the quotation marks).")

parser.add_argument("-C",
                    "--config_file",
                    default=settings._CONFIG_LOC_,
                    metavar="FILE",
                    help="read the settings from the given file; "
                         "any given settings will override the defaults. "
                         "Read from config.ini if not set.")

parser.add_argument("-v",
                    "--verbose",
                    action="store_true",
                    help="emit verbose debug output to stderr.")

parser.add_argument("-vv",
                    "--prolix",
                    action="store_true",
                    help="higher verbosity level, including extra debug "
                         "messages from dataflow analysis and elsewhere.")

parser.add_argument("-n",
                    "--no_out",
                    action="store_true",
                    help="do not output decompiled graph.")

parser.add_argument("-V",
                    "--version",
                    action="store_true",
                    help="show program's version number and exit.")

parser.add_argument("infile",
                    nargs="?",
                    type=argparse.FileType("r"),
                    default=sys.stdin,
                    help="file from which decompiler input should be read "
                         "(stdin by default).")

parser.add_argument("outfile",
                    nargs="?",
                    type=argparse.FileType("w"),
                    default=sys.stdout,
                    help="file to which decompiler output should be written "
                         "(stdout by default).")

# Parse the arguments.
args = parser.parse_args()

# Set up logger, with appropriate log level depending on verbosity.
log_level = logging.WARNING
if args.prolix:
    log_level = logging.DEBUG
elif args.verbose:
    log_level = logging.INFO
logging.basicConfig(format='%(levelname)s: %(message)s', level=log_level)

# Handle --version
if args.version:
    print(version())
    sys.exit(1)

# Always show version for log_level >= LOW
logging.info("\n" + version())

# Initialise data flow settings.
settings.import_config(args.config_file)

# Override config file with any provided settings.
if args.config is not None:
    pairs = [pair.split("=") for pair in args.config.replace(" ", "").split(",")]
    for k, v in pairs:
        settings.set_from_string(k, v)

# Build TAC CFG from input file
try:
    logging.info("Reading from '%s'.", args.infile.name)
    if args.disassembly:
        cfg = tac_cfg.TACGraph.from_dasm(args.infile)
    else:
        cfg = tac_cfg.TACGraph.from_bytecode(args.infile)
    logging.info("Initial CFG generation completed.")

# Catch a Control-C and exit with UNIX failure status 1
except KeyboardInterrupt:
    logging.critical("\nInterrupted by user")
    sys.exit(1)

# Initialise data flow settings.
settings.import_config(args.config_file)

# Override config file with any provided settings.
if args.config is not None:
    pairs = [pair.split("=") for pair in args.config.replace(" ", "").split(",")]
    for k, v in pairs:
        settings.set_from_string(k, v)

# Run data flow analysis
dataflow.analyse_graph(cfg)

# Generate output using the requested exporter(s)
if not args.no_out:
    logging.info("Writing string output.")
    print(exporter.CFGStringExporter(cfg).export(), file=args.outfile)

if args.graph is not None:
    exporter.CFGDotExporter(cfg).export(args.graph)

if args.tsv is not None:
    logging.info("Writing TSV output.")
    exporter.CFGTsvExporter(cfg).export(output_dir=args.tsv,
                                        dominators=args.dominators,
                                        out_opcodes=args.opcodes)
