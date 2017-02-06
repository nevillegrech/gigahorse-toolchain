#!/usr/bin/env python3
"""analyse_vulns.py: batch analyses smart contracts and categorises them."""


# Fetch next contract,
# decompile it,
# run analysis on it,
# add entry to mapping, with string composed of names of all non-empty output relations 
# output mapping as json file

import os
from os.path import abspath, dirname, join
import argparse
import re
from multiprocessing import Process, SimpleQueue, Manager, Event
import subprocess
import time
import sys
import itertools
import json

# Add the source directory to the path to ensure the imports work
src_path = join(dirname(abspath(__file__)), "../../src")
sys.path.insert(0, src_path)

# Local project imports
import dataflow
import tac_cfg
import opcodes
import exporter
import logger
ll = logger.log_low

# Location of Souffle binary
DEFAULT_SOUFFLE_BIN = '../../../souffle/src/souffle'

DEFAULT_CONTRACT_DIR = '../../../contract_dump/contracts'
"""Directory to fetch contract files from by default."""

DEFAULT_RESULTS_FILE = 'results.json'
"""File to write results to by default."""

DEFAULT_SPEC_DL = 'spec.dl'
"""Vulnerability specification file."""

TEMP_WORKING_DIR = ".temp"
"""Scratch working directory."""

TEMP_OUT_DIR = join(TEMP_WORKING_DIR, "out")
"""Scratch output directory."""

DEFAULT_TIMEOUT = 120
"""Default time before killing analysis of a contract."""

DEFAULT_MAX_ITER = -1
"""Default max analysis iteration count."""

DEFAULT_BAILOUT = -1
"""Default analysis bailout time in seconds."""

DEFAULT_PATTERN = ".*runtime.hex"
"""Default filename pattern for contract files."""

FLUSH_PERIOD = 3
"""Wait a little to flush the files and join the processes when concluding."""

DOMINATORS = False
"""Whether or not the cfg relations should include dominators"""

OPCODES = []
"""A list of strings indicating which opcodes to include in the cfg relations."""


parser = argparse.ArgumentParser(
  description="A batch analyser for EVM bytecode programs.")

parser.add_argument("-c",
                    "--contract_dir",
                    nargs="?",
                    default=DEFAULT_CONTRACT_DIR,
                    const=DEFAULT_CONTRACT_DIR,
                    metavar="DIR",
                    help="the location to grab contracts from (as bytecode "
                         "files).")

parser.add_argument("-S",
                    "--souffle_bin",
                    nargs="?",
                    default=DEFAULT_SOUFFLE_BIN,
                    const=DEFAULT_SOUFFLE_BIN,
                    metavar="BINARY",
                    help="the location of the souffle binary.")

parser.add_argument("-p",
                    "--filename_pattern",
                    nargs="?",
                    default=DEFAULT_PATTERN,
                    const=DEFAULT_PATTERN,
                    metavar="REGEX",
                    help="A regular expression. Only filenames matching it "
                         "will be processed.")

parser.add_argument("-r",
                    "--results_file",
                    nargs="?",
                    default=DEFAULT_RESULTS_FILE,
                    const=DEFAULT_RESULTS_FILE,
                    metavar="FILE",
                    help="the location to write the results.")

parser.add_argument("-f",
                    "--from_file",
                    nargs="?",
                    default=None,
                    metavar="FILE",
                    help="A file to extract the filenames of the contracts "
                         "to analyse from, rather than simply processing all "
                         "files in the contracts directory.")

parser.add_argument("-n",
                    "--num_contracts",
                    type=int,
                    nargs="?",
                    default=None,
                    metavar="NUM",
                    help="The maximum number of contracts to process in this "
                         "batch. Unlimited by default.")

parser.add_argument("-k",
                    "--skip",
                    type=int,
                    nargs="?",
                    default=0,
                    const=0,
                    metavar="NUM",
                    help="Skip the the analysis of the first NUM contracts.")

parser.add_argument("-t",
                    "--timeout_secs",
                    type=int,
                    nargs="?",
                    default=DEFAULT_TIMEOUT,
                    const=DEFAULT_TIMEOUT,
                    metavar="SECONDS",
                    help="Forcibly halt analysing any single contact after "
                         "the specified number of seconds.")

parser.add_argument("-I",
                    "--max_iter",
                    type=int,
                    nargs="?",
                    default=DEFAULT_MAX_ITER,
                    const=DEFAULT_MAX_ITER,
                    metavar="ITERATIONS",
                    help="perform no more than the specified number of "
                         "analysis iterations. Lower is faster, but "
                         "potentially less precise. A negative value specifies "
                         "no cap on the iteration count. No cap by default.")

parser.add_argument("-T",
                    "--bail_time",
                    type=int,
                    nargs="?",
                    default=DEFAULT_BAILOUT,
                    const=DEFAULT_BAILOUT,
                    metavar="SECONDS",
                    help="begin to terminate the analysis if it's looking to "
                         "take more time than the specified number of seconds. "
                         "Bailing out early may mean the analysis is not able "
                         "to reach a fixed-point, so results may be less "
                         "precise. A negative value means no cap on the "
                         "running time. No cap by default.")

parser.add_argument("-q",
                    "--quiet",
                    action="store_true",
                    default=False,
                    help="Silence output.")

parser.add_argument("-s",
                    "--strict",
                    action="store_true",
                    default=False,
                    help="unrecognised opcodes will not be skipped, but will "
                         "result in an error.")

def aquire_tsv_settings():
  global DOMINATORS
  global OPCODES
  dom_prefixes = ["dom", "pdom", "imdom", "impdom"]

  with open(DEFAULT_SPEC_DL, 'r') as dl:
    for line in dl:
      splitline = line.strip().split()
      if len(splitline) < 2:
        continue
      if splitline[0] == ".decl" and "input" in splitline:
        op_name = splitline[1][:splitline[1].index("(")]
        if op_name in dom_prefixes:
          DOMINATORS = True
        if op_name.startswith("op_") and op_name[3:] in opcodes.OPCODES:
          OPCODES.append(op_name[3:])

def empty_working_dirs():
  for d_triple in os.walk(TEMP_WORKING_DIR):
    for fname in d_triple[2]:
      os.remove(join(d_triple[0], fname))

def analyse_contract(filename, result_queue):
  """
  Perform dataflow analysis on a contract, storing the result in the queue.

  Args:
      filename: the location of the contract bytecode file to process
      result_queue: a multiprocessing queue in which to store the analysis results
  """
  try:
    with open(join(args.contract_dir, filename)) as file:
      cfg = tac_cfg.TACGraph.from_bytecode(file, strict=args.strict)

      dataflow.analyse_graph(cfg, max_iterations=args.max_iter,
                                  bailout_seconds=args.bail_time)

      # export relations to temp working directory
      empty_working_dirs()
      exporter.CFGTsvExporter(cfg).export(output_dir=TEMP_WORKING_DIR,
                                          dominators=DOMINATORS,
                                          out_opcodes=OPCODES)

      # run souffle on those relations
      subprocess.run([args.souffle_bin, "--fact-dir={}".format(TEMP_WORKING_DIR), 
                                        "--output-dir={}".format(TEMP_OUT_DIR),
                                        DEFAULT_SPEC_DL])

      # examine output csv files, add nonempty relation names to the vuln list
      vulns = []

      for fname in os.listdir(TEMP_OUT_DIR):
        fpath = join(TEMP_OUT_DIR, fname)
        if os.path.getsize(fpath) != 0:
          vulns.append(fname.split(".")[0])

      result_queue.put((filename, vulns))

  except Exception as e:
    ll("Error: {}".format(e))
    result_queue.put((filename, ["ERROR"]))

def flush_queue(period, run_sig,
                result_queue, result_dict):
  """
  For flushing the queue periodically to a dict so it doesn't fill up.

  Args:
      period: flush the result_queue to result_dict every period seconds
      run_sig: terminate when the Event run_sig is cleared.
      result_queue: the queue in which results accumulate before being flushed
                    to the dict.
      result_dict: the final dictionary of results.
  """
  while run_sig.is_set():
    time.sleep(period)
    while not result_queue.empty():
      item = result_queue.get()
      result_dict[item[0]] = item[1]

args = parser.parse_args()

if args.quiet:
  logger.LOG_LEVEL = logger.Verbosity.SILENT
else:
  logger.LOG_LEVEL = logger.Verbosity.MEDIUM

ll("Setting up temp working directory {}.".format(TEMP_OUT_DIR))
os.makedirs(TEMP_OUT_DIR, exist_ok=True)
empty_working_dirs()

ll("Reading TSV settings.")
aquire_tsv_settings()


# Extract contract filenames.
if args.from_file:
  # Get contract filenames from a file if specified.
  with open(args.from_file, 'r') as f:
    unfiltered = [l.strip() for l in f.readlines()]
else:
  # Otherwise just get all contracts in the contract directory.
  unfiltered = os.listdir(args.contract_dir)

# Filter according to the given pattern.
re_string = args.filename_pattern
if not re_string.endswith("$"):
  re_string = re_string + "$"
pattern = re.compile(re_string)
runtime_files = filter(lambda filename: pattern.match(filename) is not None,
                       unfiltered)

stop_index = None if args.num_contracts is None else args.skip + args.num_contracts
to_process = itertools.islice(runtime_files, args.skip, stop_index)

# Set up multiprocessing result dictionary and queue.
manager = Manager()

# This dictionary maps each filename to the analysis category it belongs to.
res_dict = manager.dict()

# Holds results transiently as (filename, category) pairs,
# frequently flushed to res_dict.
res_queue = SimpleQueue()

# Start the periodic flush process, only run while run_signal is set.
run_signal = Event()
run_signal.set()
flush_proc = Process(target=flush_queue, args=(FLUSH_PERIOD, run_signal,
                                               res_queue, res_dict))
flush_proc.start()

try:
  # Process each contract in turn, timing out if it takes too long.
  for i, fname in enumerate(to_process):
    ll("{}: {}.".format(i, fname))
    proc = Process(target=analyse_contract, args=(fname, res_queue))

    start_time = time.time()
    proc.start()

    while time.time() - start_time < args.timeout_secs:
      if proc.is_alive():
        time.sleep(0.01)
      else:
        proc.join()
        break
    else:
      res_queue.put((fname, TIMEOUT))
      proc.terminate()
      ll("Timed out.")

  # Conclude and write results to file.
  ll("\nFinishing...\n")
  run_signal.clear()
  flush_proc.join(FLUSH_PERIOD + 1)

  counts_dict = {}
  total_flagged = 0

  for contract, vulns in res_dict.items():
    if len(vulns) > 0:
      total_flagged += 1
    
    for vuln in vulns:
      if vuln not in counts_dict:
        counts_dict[vuln] = 1
      else:
        counts_dict[vuln] += 1

  total = len(res_dict)

  with open(args.results_file, 'w') as f:
    f.write(json.dumps(dict(res_dict)))
  
  ll("{} of {} contracts flagged.".format(total_flagged, total))

  for vuln, count in counts_dict.items():
    ll("{}: {:.2f}%".format(vuln, 100*count/total))

except Exception as e:
  import traceback
  traceback.print_exc()
  flush_proc.terminate()

import shutil
shutil.rmtree(TEMP_WORKING_DIR)


