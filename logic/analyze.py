#!/usr/bin/env python3

"""analyze.py: batch analyzes smart contracts and categorises them."""

## IMPORTS

import argparse
import itertools
import json
import logging
import os
import signal
import re
import subprocess
import sys
import time
import shutil
from multiprocessing import Process, SimpleQueue, Manager, Event
from os.path import abspath, dirname, join

# Add the source directory to the path to ensure the imports work
src_path = join(dirname(abspath(__file__)), "../")
sys.path.insert(0, src_path)

# Local project imports
import src.exporter as exporter
import src.blockparse as blockparse

## Constants

DEFAULT_SOUFFLE_BIN = 'souffle'
"""Location of the Souffle binary."""

DEFAULT_POROSITY_BIN = 'porosity'
"""Location of the porosity binary."""

DEFAULT_CONTRACT_DIR = 'contracts'
"""Directory to fetch contract files from by default."""

DEFAULT_RESULTS_FILE = 'results.json'
"""File to write results to by default."""

DEFAULT_DECOMPILER_DL = 'decompiler.dl'
"""Decompiler specification file."""

DEFAULT_SOUFFLE_EXECUTABLE = 'decompiler_compiled'
"""Compiled vulnerability specification file."""

TEMP_WORKING_DIR = ".temp"
"""Scratch working directory."""

DEFAULT_TIMEOUT = 120
"""Default time before killing analysis of a contract."""

DEFAULT_PATTERN = ".*runtime.hex"
"""Default filename pattern for contract files."""

FLUSH_PERIOD = 3
"""Wait a little to flush the files and join the processes when concluding."""

DEFAULT_NUM_JOBS = 4
"""The number of subprocesses to run at once."""

# Command Line Arguments

parser = argparse.ArgumentParser(
    description="A batch analyzer for EVM bytecode programs.")

parser.add_argument("-d",
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

parser.add_argument("-C",
                    "--souffle_client",
                    nargs="?",
                    default=None,
                    help="additional souffle client to run after decompilation.")


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
                         "to analyze from, rather than simply processing all "
                         "files in the contracts directory.")

parser.add_argument("-j",
                    "--jobs",
                    type=int,
                    nargs="?",
                    default=DEFAULT_NUM_JOBS,
                    const=DEFAULT_NUM_JOBS,
                    metavar="NUM",
                    help="The number of subprocesses to run at once.")

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

parser.add_argument("-T",
                    "--timeout_secs",
                    type=int,
                    nargs="?",
                    default=DEFAULT_TIMEOUT,
                    const=DEFAULT_TIMEOUT,
                    metavar="SECONDS",
                    help="Forcibly halt analysing any single contact after "
                         "the specified number of seconds.")

parser.add_argument("-q",
                    "--quiet",
                    action="store_true",
                    default=False,
                    help="Silence output.")

parser.add_argument("--no_compile",
                    action="store_true",
                    default=False,
                    help="Silence output.")

parser.add_argument("--porosity",
                    nargs="?",
                    const=DEFAULT_POROSITY_BIN,
                    metavar="BINARY",
                    help="Use the Porosity decompiler.")

# Functions
def working_dir(index: int, output_dir: bool = False) -> str:
    """
    Return a path to the working directory for the job
    indicated by index.

    Args:
     index: return the directory specifically for this index.
     output_dir: if true, return the output subdir, which souffle writes to.
    """

    if output_dir:
        return join(TEMP_WORKING_DIR, str(index), "out")
    return join(TEMP_WORKING_DIR, str(index))


def empty_working_dir(index) -> None:
   """
   Empty the working directory for the job indicated by index.
   """
   for d_triple in os.walk(working_dir(index)):
        for fname in d_triple[2]:
            os.remove(join(d_triple[0], fname))

def backup_and_empty_working_dir(index) -> None:
   # copy 
   shutil.copytree(working_dir(index), working_dir(index) + str(time.time()))

   empty_working_dir(index)
            
def compile_datalog(spec, executable):
    compilation_command = [args.souffle_bin, '-c', '-o', executable, spec]
    log("Compiling Datalog to C++ program and executable")
    process = subprocess.run(compilation_command, universal_newlines=True)
    assert not(process.returncode), "Compilation failed. Stopping."
    
    
def analyze_contract(job_index: int, index: int, filename: str, result_queue, timeout) -> None:
    """
    Perform dataflow analysis on a contract, storing the result in the queue.
    This is a worker function to be passed to a subprocess.

    Args:
        job_index: the job number for this invocation of analyze_contract
        index: the number of the particular contract being analyzed
        filename: the location of the contract bytecode file to process
        result_queue: a multiprocessing queue in which to store the analysis results
    """

    try:
        with open(join(args.contract_dir, filename)) as file:
            # Disassemble contract
            decomp_start = time.time()
            bytecode = ''.join([l.strip() for l in file if len(l.strip()) > 0])
            blocks = blockparse.EVMBytecodeParser(bytecode).parse()

            analytics = {}

            # Export relations to temp working directory
            backup_and_empty_working_dir(job_index)
            work_dir = working_dir(job_index)
            out_dir = working_dir(job_index, True)
            exporter.InstructionTsvExporter(blocks).export(output_dir=work_dir)
                                      
            contract_filename = os.path.join(os.path.join(os.getcwd(), args.contract_dir), filename)
            with open(os.path.join(work_dir, 'contract_filename.txt'),'w') as f:
                f.write(contract_filename)
            os.symlink(contract_filename, os.path.join(os.getcwd(),os.path.join(work_dir, 'contract.hex')))
            # Run souffle on those relations
            souffle_start = time.time()
            analysis_args = [os.path.join(os.getcwd(), DEFAULT_SOUFFLE_EXECUTABLE),
                             "--facts={}".format(work_dir),
                             "--output={}".format(out_dir)
            ]
            subprocess.run(analysis_args)
            if args.souffle_client:
                analysis_args = [os.path.join(os.getcwd(), args.souffle_client+'_compiled'),
                             "--facts={}".format(out_dir),
                             "--output={}".format(out_dir)
                ]
                subprocess.run(analysis_args)

            # Collect the results and put them in the result queue
            vulns = []
            for fname in os.listdir(out_dir):
                fpath = join(out_dir, fname)
                if os.path.getsize(fpath) != 0:
                    vulns.append(fname.split(".")[0])

            meta = []

            # Decompile + Analysis time
            fact_time = souffle_start - decomp_start
            souffle_time = time.time() - souffle_start
            log("{}: {:.20}... completed in {:.2f} + {:.2f} secs".format(index, filename,
                                                                         fact_time,
                                                                         souffle_time))

            analytics["fact_time"] = fact_time
            analytics["souffle_time"] = souffle_time

            get_gigahorse_analytics(out_dir, analytics)

            result_queue.put((filename, vulns, meta, analytics))

    except Exception as e:
        log("Error: {}".format(e))
        result_queue.put((filename, [], ["error"], {}))


def get_gigahorse_analytics(out_dir, analytics):
    for fname in os.listdir(out_dir):
        fpath = join(out_dir, fname)
        if not fname.startswith('Analytics_'):
            continue
        stat_name = fname.split(".")[0][10:]
        analytics[stat_name] = len(open(os.path.join(out_dir, fname)).read().split('\n'))

def run_process(args, stdout, timeout: int) -> float:
    ''' Runs process described by args, for a specific time period
    as specified by the timeout.

    Returns the time it took to run the process and -1 if the process
    times out
    '''
    start_time = time.time()
    p = subprocess.Popen(args, stdout = stdout)
    while True:
        elapsed_time = time.time() - start_time
        if p.poll() is not None:
            break
        if elapsed_time >= timeout:
            os.kill(p.pid, signal.SIGTERM)
            return -1
        time.sleep(0.1)
    return elapsed_time

def analyze_contract_porosity(job_index: int, index: int, filename: str, result_queue, timeout: int) -> None:
    try:
        contract_filename = os.path.join(os.path.join(os.getcwd(), args.contract_dir), filename)
        analytics = {}
        out_dir = working_dir(job_index, True)
        analysis_args = [DEFAULT_POROSITY_BIN,
                         '--decompile', '--code-file', contract_filename]
        f = open(out_dir+'/out.txt', "w")
        porosity_time = run_process(analysis_args, f, timeout)
        f.close()
        if porosity_time < 0:
            result_queue.put((filename, [], ["TIMEOUT"], {}))
            log("{} timed out.".format(filename))
        
        output = open(out_dir+'/out.txt').read()
        analytics['functions'] = output.count('function ')
        analytics["fact_time"] = porosity_time
        result_queue.put((filename, [], [], analytics))
        log("{}: {:.20}... completed in {:.2f} secs".format(index, filename, porosity_time))
    except Exception as e:
        log("Error: {}".format(e))
        result_queue.put((filename, [], ["error"], {}))
    

def flush_queue(period, run_sig,
                result_queue, result_list):
    """
    For flushing the queue periodically to a list so it doesn't fill up.

    Args:
        period: flush the result_queue to result_list every period seconds
        run_sig: terminate when the Event run_sig is cleared.
        result_queue: the queue in which results accumulate before being flushed
        result_list: the final list of results.
    """
    while run_sig.is_set():
        time.sleep(period)
        while not result_queue.empty():
            item = result_queue.get()
            result_list.append(item)


# Main Body

args = parser.parse_args()

log_level = logging.WARNING if args.quiet else logging.INFO + 1
log = lambda msg: logging.log(logging.INFO + 1, msg)
logging.basicConfig(format='%(message)s', level=log_level)

if args.porosity:
    args.no_compile = True

if not args.no_compile:
    compile_datalog(DEFAULT_DECOMPILER_DL, DEFAULT_SOUFFLE_EXECUTABLE)

if args.souffle_client:
    compile_datalog(args.souffle_client, args.souffle_client+'_compiled')

log("Setting up working directory {}.".format(TEMP_WORKING_DIR))
for i in range(args.jobs):
    os.makedirs(working_dir(i, True), exist_ok=True)
    empty_working_dir(i)

# Extract contract filenames.
log("Processing contract names.")
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

log("Setting up workers.")
# Set up multiprocessing result list and queue.
manager = Manager()

# This list contains analysis results as
# (filename, category, meta, analytics) quadruples.
res_list = manager.list()

# Holds results transiently before flushing to res_list
res_queue = SimpleQueue()

# Start the periodic flush process, only run while run_signal is set.
run_signal = Event()
run_signal.set()
flush_proc = Process(target=flush_queue, args=(FLUSH_PERIOD, run_signal,
                                               res_queue, res_list))
flush_proc.start()

workers = []
avail_jobs = list(range(args.jobs))
contract_iter = enumerate(to_process)
contracts_exhausted = False

if args.porosity:
    analyze_function = analyze_contract_porosity
else:
    analyze_function = analyze_contract
    

log("Analysing...\n")
try:
    while not contracts_exhausted:

        # If there's both workers and contracts available, use the former to work on the latter.
        while not contracts_exhausted and len(avail_jobs) > 0:
            try:
                index, fname = next(contract_iter)
                job_index = avail_jobs.pop()
                proc = Process(target=analyze_function, args=(job_index, index, fname, res_queue, args.timeout_secs))
                proc.start()
                start_time = time.time()
                workers.append({"name": fname,
                                "proc": proc,
                                "time": start_time,
                                "job_index": job_index})
            except StopIteration:
                contracts_exhausted = True

        # Loop until some process terminates (to retask it) or,
        # if there are no unanalyzed contracts left, until currently-running contracts are done
        while len(avail_jobs) == 0 or (contracts_exhausted and 0 < len(workers)):
            to_remove = []
            for i in range(len(workers)):
                start_time = workers[i]["time"]
                proc = workers[i]["proc"]
                name = workers[i]["name"]
                job_index = workers[i]["job_index"]

                if time.time() - start_time > (args.timeout_secs + 1):
                    res_queue.put((name, [], ["TIMEOUT"], {}))
                    proc.terminate()
                    log("{} timed out.".format(name))
                    to_remove.append(i)
                    avail_jobs.append(job_index)
                elif not proc.is_alive():
                    to_remove.append(i)
                    proc.join()
                    avail_jobs.append(job_index)

            # Reverse index order so as to pop elements correctly
            for i in reversed(to_remove):
                workers.pop(i)

            time.sleep(0.01)

    # Conclude and write results to file.
    log("\nFinishing...\n")
    run_signal.clear()
    flush_proc.join(FLUSH_PERIOD + 1)

    counts = {}
    total_flagged = 0
    for contract, vulns, meta, analytics in res_list:
        rlist = vulns + meta
        if len(rlist) > 0:
            total_flagged += 1
        for res in rlist:
            if res not in counts:
                counts[res] = 1
            else:
                counts[res] += 1

    total = len(res_list)
    log("{} of {} contracts flagged.\n".format(total_flagged, total))
    counts_sorted = sorted(list(counts.items()), key = lambda a: a[0])
    for res, count in counts_sorted:
        log("  {}: {:.2f}%".format(res, 100 * count / total))

    log("\nWriting results to {}".format(args.results_file))
    with open(args.results_file, 'w') as f:
        f.write(json.dumps(list(res_list)))

except Exception as e:
    import traceback

    traceback.print_exc()
    flush_proc.terminate()

log("Removing working directory {}".format(TEMP_WORKING_DIR))
import shutil

# shutil.rmtree(TEMP_WORKING_DIR)
