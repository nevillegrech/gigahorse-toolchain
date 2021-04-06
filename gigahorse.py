#!/usr/bin/env python3

## IMPORTS

import argparse
import itertools
import json
import logging
import signal
import shutil
import re
import subprocess
import sys
import time
import hashlib
import pathlib
from collections import defaultdict
from multiprocessing import Process, SimpleQueue, Manager, Event, cpu_count
from os.path import abspath, dirname, join, getsize
import os
from src.common import all_checkedTransferCall_filename, all_checkedTransferFromCall_filename, \
  all_readFromTrustedStorageId_filename, all_unguardedDelegateCallToSig_filename, \
  all_unguardedExternalCallToSig_filename, all_writeToUntrustedStorageId_filename

# Local project imports
import src.exporter as exporter
import src.blockparse as blockparse

devnull = subprocess.DEVNULL
GIGAHORSE_DIR = dirname(abspath(__file__))

## Constants

DEFAULT_SOUFFLE_BIN = 'souffle'
"""Location of the Souffle binary."""

DEFAULT_RESULTS_FILE = 'results.json'
"""File to write results to by default."""

DEFAULT_DECOMPILER_DL = join(GIGAHORSE_DIR, 'logic/decompiler.dl')
"""Decompiler specification file."""

DEFAULT_SOUFFLE_EXECUTABLE = 'decompiler_compiled'
"""Compiled vulnerability specification file."""

DEFAULT_INLINER_DL = join(GIGAHORSE_DIR, 'clientlib/function_inliner.dl')
"""IR helping inliner specification file."""

DEFAULT_INLINER_EXECUTABLE = 'inliner_compiled'
"""Compiled inliner file."""

DEFAULT_INLINER_ROUNDS = 4

DEFAULT_CACHE_DIR = join(GIGAHORSE_DIR, 'cache')

TEMP_WORKING_DIR = ".temp"
"""Scratch working directory."""

DEFAULT_TIMEOUT = 120
"""Default time before killing analysis of a contract."""

DEFAULT_PATTERN = ".*.hex"
"""Default filename pattern for contract files."""

DEFAULT_NUM_JOBS = max(int(cpu_count() * 0.9), 1)
"""Bugfix for one core systems."""

"""The number of subprocesses to run at once."""

# Command Line Arguments

parser = argparse.ArgumentParser(
    description="A batch analyzer for EVM bytecode programs."
)

parser.add_argument(
    "filepath",
    metavar = "DIR",
    nargs="+",
    help="The location to grab contracts from (as bytecode files). Accepts both filenames and directories. All contract filenames should be unique."
)

parser.add_argument("-S",
                    "--souffle_bin",
                    nargs="?",
                    default=DEFAULT_SOUFFLE_BIN,
                    const=DEFAULT_SOUFFLE_BIN,
                    metavar="BINARY",
                    help="the location of the souffle binary.")

parser.add_argument("-C",
                    "--client",
                    nargs="?",
                    default="",
                    help="additional clients to run after decompilation.")

parser.add_argument("-P",
                    "--pre-client",
                    nargs="?",
                    default="",
                    help="additional clients to run before decompilation.")

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

parser.add_argument("-w",
                    "--working_dir",
                    nargs="?",
                    default=TEMP_WORKING_DIR,
                    const=TEMP_WORKING_DIR,
                    metavar="DIR",
                    help="the location to were temporary files are placed.")

parser.add_argument('--cache_dir',
                    nargs="?",
                    default=DEFAULT_CACHE_DIR,
                    const=DEFAULT_CACHE_DIR,
                    metavar="DIR",
                    help="the location to were temporary files are placed.")
                    

parser.add_argument("-j",
                    "--jobs",
                    type=int,
                    nargs="?",
                    default=DEFAULT_NUM_JOBS,
                    const=DEFAULT_NUM_JOBS,
                    metavar="NUM",
                    help="The number of subprocesses to run at once.")

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

parser.add_argument("-M",
                    "--souffle_macros",
                    default = "",
                    help = "Prepocessor macro definitions to pass to Souffle using the -M parameter")

parser.add_argument("--disable_inline",
                    action="store_true",
                    default=False,
                    help="Disables the inlining of small functions (performed to produce a more high-level IR).")

parser.add_argument("-q",
                    "--quiet",
                    nargs="?",
                    default=False,
                    help="Silence output.")

parser.add_argument("--rerun_clients",
                    action="store_true",
                    default=False,
                    help="Silence output.")

parser.add_argument("--restart",
                    action="store_true",
                    default=False,
                    help="Silence output.")

parser.add_argument("--reuse_datalog_bin",
                    action="store_true",
                    default=False,
                    help="Do not recompile.")

parser.add_argument("-i",
                    "--interpreted",
                    action="store_true",
                    default=False,
                    help="Run souffle in interpreted mode.")

souffle_env = os.environ.copy()
functor_path = join(GIGAHORSE_DIR, 'souffle-addon')
souffle_env["LD_LIBRARY_PATH"] = functor_path
souffle_env["LIBRARY_PATH"] = functor_path

if not os.path.isfile(join(functor_path, 'libfunctors.so')):
    raise Exception(
        f'Cannot find libfunctors.so in {functor_path}. Make sure you have checked '\
        f'out this repo with --recursive and '\
        f'that you have installed gigahorse correctly (see README.md)'
    )

def get_working_dir(contract_name):
    return join(os.path.abspath(args.working_dir), os.path.split(contract_name)[1].split('.')[0])

def prepare_working_dir(contract_name) -> (str, str):
    newdir = get_working_dir(contract_name)
    out_dir = join(newdir, 'out')

    if os.path.isdir(newdir):
        return True, newdir, out_dir

    # recreate dir
    os.makedirs(newdir)
    os.makedirs(out_dir)
    return False, newdir, out_dir

def compile_datalog(spec, executable):
    if args.reuse_datalog_bin and os.path.isfile(executable):
        return

    pathlib.Path(args.cache_dir).mkdir(exist_ok=True)

    souffle_macros = f'GIGAHORSE_DIR={GIGAHORSE_DIR} BULK_ANALYSIS= {args.souffle_macros}'.strip()

    cpp_macros = []
    for macro_def in souffle_macros.split(' '):
        cpp_macros.append('-D')
        cpp_macros.append(macro_def)

    preproc_command = ['cpp', '-P', spec] + cpp_macros
    preproc_process = subprocess.run(preproc_command, universal_newlines=True, capture_output=True)
    assert not(preproc_process.returncode), f"Preprocessing for {spec} failed. Stopping."

    hasher = hashlib.md5()
    hasher.update(preproc_process.stdout.encode('utf-8'))
    md5_hash = hasher.hexdigest()

    cache_path = join(args.cache_dir, md5_hash)

    if os.path.exists(cache_path):
        log(f"Found cached executable for {spec}")
    else:
        log(f"Compiling {spec} to C++ program and executable")
        compilation_command = [args.souffle_bin, '-c', '-M', souffle_macros, '-o', cache_path, spec]
        process = subprocess.run(compilation_command, universal_newlines=True, env = souffle_env)
        assert not(process.returncode), "Compilation failed. Stopping."

    shutil.copy2(cache_path, executable)
    
    
def analyze_contract(job_index: int, index: int, contract_filename: str, result_queue, timeout) -> None:
    """
    Perform dataflow analysis on a contract, storing the result in the queue.
    This is a worker function to be passed to a subprocess.

    Args:
        job_index: the job number for this invocation of analyze_contract
        index: the number of the particular contract being analyzed
        contract_filename: the absolute path of the contract bytecode file to process
        result_queue: a multiprocessing queue in which to store the analysis results
    """

    try:
        # prepare working directory
        exists, work_dir, out_dir = prepare_working_dir(contract_filename)
        assert not(args.restart and exists)
        analytics = {}
        contract_name = os.path.split(contract_filename)[1]
        disassemble_start = time.time()
        def calc_timeout():
            return timeout-time.time()+disassemble_start
        if exists:
            decomp_start = time.time()
            inline_start = time.time()
        else:
            with open(contract_filename) as file:
                bytecode = file.read().strip()

            # Disassemble contract
            blocks = blockparse.EVMBytecodeParser(bytecode).parse()
            exporter.InstructionTsvExporter(blocks).export(output_dir=work_dir, bytecode_hex=bytecode)

            os.symlink(join(work_dir, 'bytecode.hex'), join(out_dir, 'bytecode.hex'))
            
            # Run pre-clients
            for souffle_client in souffle_pre_clients:
                if not args.interpreted:
                    analysis_args = [join(os.getcwd(), souffle_client+'_compiled'),
                                 "--facts={}".format(work_dir),
                                 "--output={}".format(work_dir)
                    ]
                else:
                    analysis_args = [DEFAULT_SOUFFLE_BIN,
                                 join(os.getcwd(), souffle_client),
                                 "--fact-dir={}".format(work_dir),
                                 "--output-dir={}".format(work_dir)
                    ]
                runtime = run_process(analysis_args, calc_timeout())
                if runtime < 0:
                    result_queue.put((contract_name, [], ["TIMEOUT"], {}))
                    log("{} timed out.".format(contract_name))
                    return

            for other_client in other_pre_clients:
                other_client_split = [o for o in other_client.split(' ') if o]
                other_client_split[0] = join(os.getcwd(), other_client_split[0])
                other_client_name = other_client_split[0].split('/')[-1]
                out_filename = join(work_dir, other_client_name+'.out')
                err_filename = join(work_dir, other_client_name+'.err')
                runtime = run_process(
                    other_client_split,
                    calc_timeout(),
                    open(out_filename, 'w'),
                    open(err_filename, 'w'),
                    cwd=work_dir
                )
                if runtime < 0:
                    result_queue.put((contract_name, [], ["TIMEOUT"], {}))
                    log("{} timed out.".format(contract_name))
                    return

            
            # Run souffle on those relations
            decomp_start = time.time()

            if not args.interpreted:
                analysis_args = [join(os.getcwd(), DEFAULT_SOUFFLE_EXECUTABLE),
                             "--facts={}".format(work_dir),
                             "--output={}".format(out_dir)
                ]
            else:
                analysis_args = [DEFAULT_SOUFFLE_BIN,
                             DEFAULT_DECOMPILER_DL,
                             "--fact-dir={}".format(work_dir),
                             "--output-dir={}".format(out_dir)
                ]

            runtime = run_process(analysis_args, calc_timeout())
            if runtime < 0:
                result_queue.put((contract_filename, [], ["TIMEOUT"], {}))
                log("{} timed out.".format(contract_filename))
                return
            
            for filename in [all_checkedTransferCall_filename, all_checkedTransferFromCall_filename,
                  all_readFromTrustedStorageId_filename, all_unguardedDelegateCallToSig_filename,
                  all_unguardedExternalCallToSig_filename, all_writeToUntrustedStorageId_filename]:
                basename = os.path.basename(filename)
                filename_out = os.path.join(out_dir, basename)
                if os.path.isfile(filename):
                    try:
                        os.symlink(filename, filename_out)
                    except FileExistsError:
                        pass
                else:
                    open(filename_out, 'w').close()
            
            inline_start = time.time()
            if not args.disable_inline:
                if not args.interpreted:
                    inliner_args = [join(os.getcwd(), DEFAULT_INLINER_EXECUTABLE),
                                "--facts={}".format(out_dir),
                                "--output={}".format(out_dir)
                    ]
                else:
                    inliner_args = [DEFAULT_SOUFFLE_BIN,
                                DEFAULT_INLINER_DL,
                                "--fact-dir={}".format(out_dir),
                                "--output-dir={}".format(out_dir)
                    ]
                for i in range(DEFAULT_INLINER_ROUNDS):
                   runtime = run_process(inliner_args, calc_timeout())
                   needs_more_file = join(out_dir, 'NeedsMoreInlining.csv')
                   if os.path.exists(needs_more_file):
                       if os.path.getsize(needs_more_file) == 0:
                           break
                    
            # end decompilation
        if exists and not args.rerun_clients:
            return
        client_start = time.time()
        for souffle_client in souffle_clients:
            if not args.interpreted:
                analysis_args = [join(os.getcwd(), souffle_client+'_compiled'),
                             "--facts={}".format(out_dir),
                             "--output={}".format(out_dir)
                ]
            else:
                analysis_args = [DEFAULT_SOUFFLE_BIN,
                             join(os.getcwd(), souffle_client),
                             "--fact-dir={}".format(out_dir),
                             "--output-dir={}".format(out_dir)
                ]
            runtime = run_process(analysis_args, calc_timeout())
            if runtime < 0:
                result_queue.put((contract_name, [], ["TIMEOUT"], {}))
                log("{} timed out.".format(contract_name))
                return
        for other_client in other_clients:
            other_client_split = [o for o in other_client.split(' ') if o]
            other_client_split[0] = join(os.getcwd(), other_client_split[0])
            other_client_name = other_client_split[0].split('/')[-1]
            out_filename = join(out_dir, other_client_name+'.out')
            err_filename = join(out_dir, other_client_name+'.err')
            runtime = run_process(
                other_client_split,
                calc_timeout(),
                open(out_filename, 'w'),
                open(err_filename, 'w'),
                cwd = out_dir
            )
            if runtime < 0:
                result_queue.put((contract_name, [], ["TIMEOUT"], {}))
                log("{} timed out.".format(contract_name))
                return
            
        # Collect the results and put them in the result queue
        files = []
        for fname in os.listdir(out_dir):
            fpath = join(out_dir, fname)
            if getsize(fpath) != 0:
                files.append(fname.split(".")[0])
        meta = []
        # Decompile + Analysis time
        analytics['disassemble_time'] = decomp_start - disassemble_start
        analytics['decomp_time'] = inline_start - decomp_start
        analytics['inline_time'] = client_start - inline_start
        analytics['client_time'] = time.time() - client_start
        log("{}: {:.36} completed in {:.2f} + {:.2f} + {:.2f} + {:.2f} secs".format(
            index, contract_name, analytics['disassemble_time'],
            analytics['decomp_time'], analytics['inline_time'], analytics['client_time']
        ))

        get_gigahorse_analytics(out_dir, analytics)

        result_queue.put((contract_name, files, meta, analytics))

    except Exception as e:
        log("Error: {}".format(e))
        result_queue.put((contract_name, [], ["error"], {}))


def get_gigahorse_analytics(out_dir, analytics):
    for fname in os.listdir(out_dir):
        fpath = join(out_dir, fname)
        if not fname.startswith('Analytics_'):
            continue
        stat_name = fname.split(".")[0]
        analytics[stat_name] = sum(1 for line in open(join(out_dir, fname)))

    for fname in os.listdir(out_dir):
        fpath = join(out_dir, fname)
        if not fname.startswith('Verbatim_'):
            continue
        stat_name = fname.split(".")[0]
        analytics[stat_name] = open(join(out_dir, fname)).read()

    for desc_fname in os.listdir(out_dir):
        if desc_fname.startswith('VulnerabilityDescription_'):
            fname = desc_fname[25:]
            stat_name = fname.split(".")[0]
            fpath = join(out_dir, fname)
            if os.path.exists(fpath):
                analytics[stat_name] = open(fpath).read()
            else:
                analytics[stat_name] = ''

def run_process(args, timeout: int, stdout = devnull, stderr = devnull, cwd = '.') -> float:
    ''' Runs process described by args, for a specific time period
    as specified by the timeout.

    Returns the time it took to run the process and -1 if the process
    times out
    '''
    if timeout < 0:
        return -1
    start_time = time.time()
    p = subprocess.Popen(args, stdout = stdout, stderr = stderr, cwd = cwd, env = souffle_env)
    while True:
        elapsed_time = time.time() - start_time
        if p.poll() is not None:
            break
        if elapsed_time >= timeout:
            os.kill(p.pid, signal.SIGTERM)
            return -1
        time.sleep(0.01)
    return elapsed_time

def flush_queue(run_sig, result_queue, result_list):
    """
    For flushing the queue periodically to a list so it doesn't fill up.

    Args:
        period: flush the result_queue to result_list every period seconds
        run_sig: terminate when the Event run_sig is cleared.
        result_queue: the queue in which results accumulate before being flushed
        result_list: the final list of results.
    """
    while run_sig.is_set():
        time.sleep(0.1)
        while not result_queue.empty():
            item = result_queue.get()
            result_list.append(item)

# Main Body
args = parser.parse_args()

log_level = logging.WARNING if args.quiet else logging.INFO + 1
log = lambda msg: logging.log(logging.INFO + 1, msg)
logging.basicConfig(format='%(message)s', level=log_level)

# Here we compile the decompiler and any of its clients in parallel :)
compile_processes_args = []
compile_processes_args.append((DEFAULT_DECOMPILER_DL, DEFAULT_SOUFFLE_EXECUTABLE))

if not args.disable_inline:
    compile_processes_args.append((DEFAULT_INLINER_DL, DEFAULT_INLINER_EXECUTABLE))

clients_split = [a.strip() for a in args.client.split(',')]
souffle_clients = [a for a in clients_split if a.endswith('.dl')]
other_clients = [a for a in clients_split if not (a.endswith('.dl') or a == '')]

pre_clients_split = [a.strip() for a in args.pre_client.split(',')]
souffle_pre_clients = [a for a in pre_clients_split if a.endswith('.dl')]
other_pre_clients = [a for a in pre_clients_split if not (a.endswith('.dl') or a == '')]

if not args.interpreted:
    for c in souffle_pre_clients:
        compile_processes_args.append((c, c+'_compiled'))

    for c in souffle_clients:
        compile_processes_args.append((c, c+'_compiled'))

    running_processes = []
    for compile_args in compile_processes_args:
        proc = Process(target = compile_datalog, args=compile_args)
        proc.start()
        running_processes.append(proc)

if args.restart:
    log("Removing working directory {}".format(args.working_dir))
    shutil.rmtree(args.working_dir, ignore_errors = True)    
    
if not args.interpreted:
    for p in running_processes:
        p.join()

    # check all programs have been compiled
    for _, v in compile_processes_args:
        open(v, 'r') # check program exists

# Extract contract filenames.
log("Processing contract names.")

contracts = []

# Filter according to the given pattern.
re_string = args.filename_pattern
if not re_string.endswith("$"):
    re_string = re_string + "$"
pattern = re.compile(re_string)


for filepath in args.filepath:
    if os.path.isdir(filepath):
        if args.interpreted:
            log("[WARNING]: Running batch analysis in interpreted mode.")
        unfiltered = [join(filepath, f) for f in os.listdir(filepath)]
    else:
        unfiltered = [filepath]
        
    contracts += [u for u in unfiltered if pattern.match(u) is not None]

contracts = contracts[args.skip:]


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
flush_proc = Process(target=flush_queue, args=(run_signal, res_queue, res_list))
flush_proc.start()

workers = []
avail_jobs = list(range(args.jobs))
contract_iter = enumerate(contracts)
contracts_exhausted = False

log("Analysing...\n")
try:
    while not contracts_exhausted:
        # If there's both workers and contracts available, use the former to work on the latter.
        while not contracts_exhausted and len(avail_jobs) > 0:
            try:
                index, contract_name = next(contract_iter)
                working_dir = get_working_dir(contract_name)
                if os.path.isdir(working_dir) and not args.rerun_clients:
                    # no need to create another process
                    continue

                # reduce number of available jobs
                job_index = avail_jobs.pop()
                proc = Process(target=analyze_contract, args=(job_index, index, contract_name, res_queue, args.timeout_secs))
                proc.start()
                start_time = time.time()
                workers.append({"name": contract_name,
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
    run_signal.clear()
    flush_proc.join(1)
    # it's important to count the total after proc.join
    total = len(res_list)
    log(f"\nFinished {total} contracts...\n")

    vulnerability_counts = defaultdict(int)
    analytics_sums = defaultdict(int)
    meta_counts = defaultdict(int)
    all_files = set()
    for contract, files, meta, analytics in res_list:
        for f in files:
            all_files.add(f)
        for m in meta:
            meta_counts[m] += 1
        for k, a in analytics.items():
            if isinstance(a, int):
                analytics_sums[k] += a
            if isinstance(a, str) and not k.startswith('Verbatim_'):
                # whether it's flagged or not
                vulnerability_counts[k] += int(len(a) > 0)
            if k in all_files:
                all_files.remove(k)

    analytics_sums_sorted = sorted(list(analytics_sums.items()), key = lambda a: a[0])
    if analytics_sums_sorted:
        log('\n')
        log('-'*80)
        log('Analytics')
        log('-'*80)
        for res, sums in analytics_sums_sorted:
            log("  {}: {}".format(res, sums))
        log('\n')
        
    vulnerability_counts_sorted = sorted(list(vulnerability_counts.items()), key = lambda a: a[0])
    if vulnerability_counts_sorted:
        log('-'*80)
        log('Summary (flagged contracts)')
        log('-'*80)
    
        for res, count in vulnerability_counts_sorted:
            log("  {}: {:.2f}%".format(res, 100 * count / total))

    if meta_counts:
        log('-'*80)
        log('Timeouts and Errors')
        log('-'*80)
        for k, v in meta_counts.items():
            log(f"  {k}: {v} of {total} contracts")
        log('\n')
            
    log("\nWriting results to {}".format(args.results_file))
    with open(args.results_file, 'w') as f:
        f.write(json.dumps(list(res_list), indent=1))

except Exception as e:
    import traceback

    traceback.print_exc()
    flush_proc.terminate()
