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


"""analyse_opcodes.py: produces aggregate opcode stats from EVM bytecode"""

import argparse
import collections
import csv
import glob
import math
import os
import sys
import typing as t

# Add the source directory to the path to ensure the imports work
from os.path import abspath, dirname, join

src_path = join(dirname(abspath(__file__)), "../../")
sys.path.insert(0, src_path)

# decompiler project imports
import src.blockparse as blockparse
import src.opcodes as opcodes

DEFAULT_CONTRACT_DIR = 'contracts'
"""Directory to fetch contract files from by default."""

CONTRACT_GLOB = '*_runtime.hex'
"""Files in the contract_dir which match this glob will be processed"""

CSV_FIELDS = ['contract'] + list(sorted(opcodes.OPCODES.keys())) + ['total']
"""fields to appear in output CSV, in this order"""

parser = argparse.ArgumentParser()

parser.add_argument("-c",
                    "--contract_dir",
                    nargs="?",
                    default=DEFAULT_CONTRACT_DIR,
                    const=DEFAULT_CONTRACT_DIR,
                    metavar="DIR",
                    help="the location to grab contracts from (as bytecode "
                         "files).")

parser.add_argument('outfile',
                    type=argparse.FileType('w'),
                    help="CSV file where output statistics will be written, "
                         "one row per contract, with a CSV header as row 1. "
                         "Defaults to stdout if not specified.")

args = parser.parse_args()


def print_progress(progress: int, item: str = ""):
    """
    print_progress prints or updates a progress bar with a progress between 0
    and 100.  If given, item is an arbitrary string to be displayed adjacent to
    the progress bar.
    """
    WIDTH = 25
    hashes = min(int(math.floor(progress / (100 // WIDTH))), WIDTH)
    sys.stdout.write('\r[{}] {}% {} '.format('#' * hashes + ' ' * (WIDTH - hashes),
                                             progress, item))
    if (progress == 100):
        sys.stdout.write('\n')
    sys.stdout.flush()


def count_opcodes(bytecode: t.Union[str, bytes]) -> collections.Counter:
    """
    count_opcodes counts the number of each type of opcode from a given bytecode
    sequence, returning a dict-compatible collections.Counter.
    """
    parser = blockparse.EVMBytecodeParser(bytecode)
    parser.parse()

    # convert EVMOps to OpCodes
    ops = list(map(lambda op: op.opcode, parser._ops))

    # use Python's Counter to count each
    return collections.Counter(ops), ops


print("Searching for files...")
pattern = join(args.contract_dir, CONTRACT_GLOB)
files = glob.glob(pattern)
print("Located {} contract files matching {}".format(len(files), pattern))

print("Writing output to {}".format(args.outfile.name))

writer = csv.DictWriter(args.outfile, restval=0, fieldnames=CSV_FIELDS)
writer.writeheader()

for i, fname in enumerate(files):
    with open(fname, 'r') as f:
        bname = os.path.basename(f.name)

        # update a progress bar after processing 10 contracts
        if i % 10 == 0 or i + 1 == len(files):
            print_progress(math.floor((i + 1) / len(files) * 100),
                           "{}/{} {}".format(i + 1, len(files), bname))

        counts, ops = count_opcodes(f.read().strip())
        row = {op.name: count for op, count in counts.items()}

        # add a "total" column to each row
        row['total'] = sum(row.values())

        # contract filename always goes in first CSV field
        row[CSV_FIELDS[0]] = bname
        writer.writerow(row)
