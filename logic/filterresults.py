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

"""filter_results.py: filter down the results from analyse.py"""

import argparse
import json

JSON_FILE = "results.json"

parser = argparse.ArgumentParser()
parser.add_argument("-i",
                    "--in_file",
                    nargs="?",
                    default=JSON_FILE,
                    const=JSON_FILE,
                    metavar="FILEPATH",
                    help="take input from the specified file."
                    )

parser.add_argument("-n",
                    "--names_only",
                    default=False,
                    action="store_true",
                    help="output filenames only."
                    )

parser.add_argument("-p",
                    "--properties",
                    nargs="*",
                    default=[],
                    metavar="NAME",
                    help="include results exhibiting all of the given properties."
                    )

parser.add_argument("-P",
                    "--exclude_properties",
                    nargs="*",
                    default=[],
                    metavar="NAME",
                    help="exclude results exhibiting any of the given properties."
                    )

parser.add_argument("-f",
                    "--flags",
                    nargs="*",
                    default=[],
                    metavar="NAME",
                    help="include results exhibiting all of the given flags."
                    )

parser.add_argument("-F",
                    "--exclude_flags",
                    nargs="*",
                    default=[],
                    metavar="NAME",
                    help="exclude results exhibiting any of the given flags."
                    )

args = parser.parse_args()


def satisfies(triple):
    """
    Args:
      triple: a triple of [filename, properties, flags]
  
    Returns:
      True iff the conditions specified in the args are satisfied.
    """
    filename, properties, flags = triple

    for p in args.properties:
        if p not in properties:
            return False

    for f in args.flags:
        if f not in flags:
            return False

    for p in args.exclude_properties:
        if p in properties:
            return False

    for f in args.exclude_flags:
        if f in flags:
            return False

    # result satisfied the filter => return True
    return True


with open(args.in_file, 'r') as f:
    results = json.loads(f.read())
    with open("filtered_results.json", 'w') as g:
        filtered = filter(satisfies, results)
        if args.names_only:
            filtered = map(lambda t: t[0], filtered)
        filtered = list(filtered)
        print("{} results filtered down to {}.".format(len(results), len(filtered)))
        g.write(json.dumps(filtered))
