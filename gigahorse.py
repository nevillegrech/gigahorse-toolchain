#!/usr/bin/env python3

## IMPORTS

import argparse
import itertools
import json
import logging
import signal
import resource
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

SOUFFLE_COMPILED_SUFFIX = '_compiled'

DEFAULT_DECOMPILER_DL = join(GIGAHORSE_DIR, 'logic/main.dl')
"""Decompiler specification file."""

FALLBACK_SCALABLE_DECOMPILER_DL = join(GIGAHORSE_DIR, 'logic/fallback_scalable.dl')
"""Fallback decompiler specification file, optimized for scalability."""

FALLBACK_PRECISE_DECOMPILER_DL = join(GIGAHORSE_DIR, 'logic/fallback_precise.dl')
"""Alternative decompiler version that uses cues from previous round's decompilation to be more precise."""

DEFAULT_INLINER_DL = join(GIGAHORSE_DIR, 'clientlib/function_inliner.dl')
"""IR helping inliner specification file."""

DEFAULT_INLINER_ROUNDS = 6

DEFAULT_CACHE_DIR = join(GIGAHORSE_DIR, 'cache')

TEMP_WORKING_DIR = ".temp"
"""Scratch working directory."""

DEFAULT_TIMEOUT = 120
"""Default time before killing analysis of a contract."""

DEFAULT_MINIMUM_CLIENT_TIME = 10
"""Default minimum time to allow each client to work."""

DEFAULT_PATTERN = ".*.hex"
"""Default filename pattern for contract files."""

DEFAULT_NUM_JOBS = max(int(cpu_count() * 0.9), 1)
"""Bugfix for one core systems."""

"""The number of subprocesses to run at once."""

DEFAULT_MEMORY_LIMIT = 45 * 1_000_000_000
"""Hard capped memory limit for analyses processes (30 GB)"""

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

parser.add_argument("--minimum_client_time",
                    type=int,
                    nargs="?",
                    default=DEFAULT_MINIMUM_CLIENT_TIME,
                    const=DEFAULT_MINIMUM_CLIENT_TIME,
                    metavar="SECONDS",
                    help="Minimum time to allow each client to run.")

parser.add_argument("-M",
                    "--souffle_macros",
                    default = "",
                    help = "Prepocessor macro definitions to pass to Souffle using the -M parameter")

parser.add_argument("-cd",
                    "--context_depth",
                    type=int,
                    nargs="?",
                    metavar="NUM",
                    help="Override the maximum context depth for decompilation (default is 8).")

parser.add_argument("--enable_limitsize",
                    action="store_true",
                    default=False,
                    help= ("Adds a limitsize (see souffle documentation) that limits the outputs"
                        "of certain key decompiler relations to improve scalability."
                        "Can make decompilation output more incomplete and imprecise."
                        )
                    )

parser.add_argument("--disable_inline",
                    action="store_true",
                    default=False,
                    help="Disables the inlining of small functions performed after TAC code is generated"
                    " (to increase the amount of high level inferences produced by the memory and storage modeling components).")

parser.add_argument("--early_cloning",
                    action="store_true",
                    default=False,
                    help="Adds a cloning pre-process step (targetting blocks that can cause imprecision) to the decompilation pipeline.")

parser.add_argument("--disable_precise_fallback",
                    action="store_true",
                    default=False,
                    help="Disables the precise fallback configuration (same as the --early_cloning flag) that kicks off if decompilation"
                    " with the default (transactional) config is successful but produces imprecise results.")

parser.add_argument("--disable_scalable_fallback",
                    action="store_true",
                    default=False,
                    help="Disables the scalable fallback configuration (using a hybrid-precise context configuration) that kicks off"
                    " if decompilation with the default (transactional) config takes up more than half of the total timeout.")

parser.add_argument("-q",
                    "--quiet",
                    nargs="?",
                    default=False,
                    help="Silence output.")

parser.add_argument("--rerun_clients",
                    action="store_true",
                    default=False,
                    help="Rerun previously executed client analyses.")

parser.add_argument("--restart",
                    action="store_true",
                    default=False,
                    help="Erase working dir and decompile/analyze from scratch.")

parser.add_argument("--reuse_datalog_bin",
                    action="store_true",
                    default=False,
                    help="Do not recompile the datalog binaries.")

parser.add_argument("-i",
                    "--interpreted",
                    action="store_true",
                    default=False,
                    help="Run souffle in interpreted mode.")


souffle_env = os.environ.copy()
functor_path = join(GIGAHORSE_DIR, 'souffle-addon')
for e in ["LD_LIBRARY_PATH", "LIBRARY_PATH"]:
    if e in souffle_env:
        souffle_env[e] = functor_path + os.pathsep + souffle_env[e]
    else:
        souffle_env[e] = functor_path

if not os.path.isfile(join(functor_path, 'libfunctors.so')):
    raise Exception(
        f'Cannot find libfunctors.so in {functor_path}. Make sure you have checked '\
        f'out this repo with --recursive and '\
        f'that you have installed gigahorse correctly (see README.md)'
    )

def get_working_dir(contract_name):
    return join(os.path.abspath(args.working_dir), os.path.split(contract_name)[1].split('.')[0])

def prepare_working_dir(contract_name) -> (bool, str, str, str):
    newdir = get_working_dir(contract_name)
    out_dir = join(newdir, 'out')
    fallback_out_dir = join(newdir, 'fallbackout')

    if os.path.isdir(newdir):
        return True, newdir, out_dir, fallback_out_dir

    # recreate dir
    os.makedirs(newdir)
    os.makedirs(out_dir)
    os.makedirs(fallback_out_dir)
    return False, newdir, out_dir, fallback_out_dir

def get_souffle_macros():
    souffle_macros = f'GIGAHORSE_DIR={GIGAHORSE_DIR} BULK_ANALYSIS= {args.souffle_macros}'.strip()

    if args.enable_limitsize:
        souffle_macros+=' ENABLE_LIMITSIZE='

    if args.early_cloning:
        souffle_macros+=' BLOCK_CLONING=HeuristicBlockCloner'

    return souffle_macros

def write_context_depth_file(filename, max_context_depth):
    context_depth_file = open(filename, "w")
    context_depth_file.write(f"{max_context_depth}\n")
    context_depth_file.close()

def compile_datalog(spec, executable):
    if args.reuse_datalog_bin and os.path.isfile(executable):
        return

    pathlib.Path(args.cache_dir).mkdir(exist_ok=True)

    souffle_macros = get_souffle_macros()

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
        compilation_command = [args.souffle_bin, '-M', souffle_macros, '-o', cache_path, spec, '-L', functor_path]
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
    disassemble_start = time.time()
    
    def calc_timeout(souffle_client =None):
        timeout_left = timeout-time.time()+disassemble_start

        if not args.disable_scalable_fallback and souffle_client == DEFAULT_DECOMPILER_DL:
            timeout_left = timeout_left/2

        return max(timeout_left, args.minimum_client_time)

    
    def run_clients(souffle_clients, other_clients, in_dir, out_dir):
        errors = []
        timeouts = []
        for souffle_client in souffle_clients:
            if not args.interpreted:
                analysis_args = [
                    join(os.getcwd(), souffle_client+SOUFFLE_COMPILED_SUFFIX),
                    f"--facts={in_dir}", f"--output={out_dir}"
                ]
            else:
                analysis_args = [
                    DEFAULT_SOUFFLE_BIN,
                    join(os.getcwd(), souffle_client),
                    f"--fact-dir={in_dir}", f"--output-dir={out_dir}",
                    "-M", get_souffle_macros()
                ]
            if run_process(analysis_args, calc_timeout(souffle_client)) < 0:
                timeouts.append(souffle_client)

        for other_client in other_clients:
            other_client_split = [o for o in other_client.split(' ') if o]
            other_client_split[0] = join(os.getcwd(), other_client_split[0])
            other_client_name = other_client_split[0].split('/')[-1]
            err_filename = join(out_dir, other_client_name+'.err')
            
            runtime = run_process(
                other_client_split,
                calc_timeout(),
                devnull,
                open(err_filename, 'w'),
                cwd=in_dir
            )
            if len(open(err_filename).read()) > 0:
                errors.append(other_client_name)
            if runtime < 0:
                timeouts.append(other_client)
        return timeouts, errors
    
    def run_decomp(contract_filename, in_dir, out_dir, fallback_out_dir):

        config = "default"
        def_timeouts, _ = run_clients([DEFAULT_DECOMPILER_DL], [], in_dir, out_dir)

        if not args.disable_precise_fallback and not def_timeouts and decomp_out_produced(out_dir):
            # try the precise configuration only if the default didn't take more 0.3 of the total timeout
            # this was chosen because on average the precise decompiler takes about 2x the time of the default one
            if imprecise_decomp_out(out_dir) and calc_timeout(FALLBACK_PRECISE_DECOMPILER_DL) > 0.3 * timeout:
                log(f"Using precise fallback decompilation configuration for {os.path.split(contract_filename)[1]}")

                pre_timeouts, _ = run_clients([FALLBACK_PRECISE_DECOMPILER_DL], [], in_dir, fallback_out_dir)
                if not pre_timeouts and decomp_out_produced(fallback_out_dir):
                    shutil.rmtree(out_dir)
                    os.rename(fallback_out_dir, out_dir)
                    config = "precise"

        elif def_timeouts or not decomp_out_produced(out_dir):
            if args.disable_scalable_fallback:
                raise TimeoutException()
            else:
                # Default using scalable fallback config
                log(f"Using scalable fallback decompilation configuration for {os.path.split(contract_filename)[1]}")
                write_context_depth_file(os.path.join(in_dir, 'MaxContextDepth.csv'), 1)

                sca_timeouts, _ = run_clients([FALLBACK_SCALABLE_DECOMPILER_DL], [], in_dir, out_dir)
                if not sca_timeouts and decomp_out_produced(out_dir):
                    config = "scalable"
                else:
                    raise TimeoutException()

        return config

    def imprecise_decomp_out(out_dir):
        """Used to check if decompilation output is imprecise, currently only checks Analytics_JumpToMany"""
        imprecision_metric = len(open(join(out_dir, 'Analytics_JumpToMany.csv'), 'r').readlines())
        return imprecision_metric > 0

    def decomp_out_produced(out_dir):
        """Hacky. Needed to ensure process was not killed due to exceeding the memory limit."""
        return os.path.exists(join(out_dir, 'Analytics_JumpToMany.csv')) and os.path.exists(join(out_dir, 'TAC_Def.csv'))

    try:
        # prepare working directory
        exists, work_dir, out_dir, fallback_out_dir = prepare_working_dir(contract_filename)
        assert not(args.restart and exists)
        analytics = {}
        contract_name = os.path.split(contract_filename)[1]
        with open(contract_filename) as file:
            bytecode = file.read().strip()

        if exists:
            decomp_start = time.time()
            inline_start = time.time()
            decompiler_config = None
        else:
            # Disassemble contract
            blocks = blockparse.EVMBytecodeParser(bytecode).parse()
            exporter.InstructionTsvExporter(blocks).export(output_dir=work_dir, bytecode_hex=bytecode)

            os.symlink(join(work_dir, 'bytecode.hex'), join(out_dir, 'bytecode.hex'))

            if os.path.exists(join(work_dir, 'compiler_info.csv')):
                # Create a symlink with a name starting with 'Verbatim_' to be added to results json
                os.symlink(join(work_dir, 'compiler_info.csv'), join(out_dir, 'Verbatim_compiler_info.csv'))
                os.symlink(join(work_dir, 'compiler_info.csv'), join(fallback_out_dir, 'Verbatim_compiler_info.csv'))

            timeouts, _ = run_clients(souffle_pre_clients, other_pre_clients, work_dir, work_dir)
            if timeouts:
                # pre clients should be very light, should never happen
                raise TimeoutException()

            if args.context_depth is not None:
                write_context_depth_file(os.path.join(work_dir, 'MaxContextDepth.csv'), args.context_depth)

            decomp_start = time.time()

            decompiler_config = run_decomp(contract_filename, work_dir, out_dir, fallback_out_dir)

            inline_start = time.time()
            if not args.disable_inline:
                # ignore timeouts and errors here
                run_clients([DEFAULT_INLINER_DL]*DEFAULT_INLINER_ROUNDS, [], out_dir, out_dir)

            # end decompilation
        if exists and not args.rerun_clients:
            return
        client_start = time.time()
        timeouts, errors = run_clients(souffle_clients, other_clients, out_dir, out_dir)

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
        analytics['errors'] = len(errors)
        analytics['client_timeouts'] = len(timeouts)
        analytics['bytecode_size'] = (len(bytecode) - 2)//2
        analytics['decompiler_config'] = decompiler_config
        contract_msg = "{}: {:.36} completed in {:.2f} + {:.2f} + {:.2f} + {:.2f} secs.".format(
            index, contract_name, analytics['disassemble_time'],
            analytics['decomp_time'], analytics['inline_time'], analytics['client_time']
        )
        if errors:
            meta.append("CLIENT ERROR")
            contract_msg += f" Errors in: {', '.join(errors)}."
        if timeouts:
            meta.append("CLIENT TIMEOUT")
            contract_msg += f" Timeouts in: {', '.join(timeouts)}."

        log(contract_msg)

        get_gigahorse_analytics(out_dir, analytics)

        result_queue.put((contract_name, files, meta, analytics))
    except TimeoutException as e:
        result_queue.put((contract_name, [], ["TIMEOUT"], {}))
        log("{} timed out.".format(contract_name))
    except Exception as e:
        log(f"Error: {e}")
        result_queue.put((contract_name, [], ["ERROR"], {}))


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

    vul_types = defaultdict(int)
    try:
        f = open(join(out_dir, 'vulnerability.csv'))
    except FileNotFoundError:
        return
    for raw_line in f:
        line_split = raw_line.split('\t')
        if line_split:
            vulnerability_type, confidence, *_ = line_split
            key = f'{confidence}: {vulnerability_type}'
            analytics[key] = analytics.get(key, 0) + 1

def set_memory_limit(memory_limit):
    resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))

class TimeoutException(Exception):
    pass

def run_process(process_args, timeout: int, stdout=devnull, stderr=devnull, cwd: str='.', memory_limit=DEFAULT_MEMORY_LIMIT) -> float:
    ''' Runs process described by args, for a specific time period
    as specified by the timeout.

    Returns the time it took to run the process and -1 if the process
    times out
    '''
    if timeout < 0:
        # This can theoretically happen
        return -1

    start_time = time.time()

    try:
        subprocess.run(process_args, timeout=timeout, stdout=stdout, stderr=stderr, cwd=cwd, env=souffle_env, preexec_fn=lambda: set_memory_limit(memory_limit))
    except subprocess.TimeoutExpired:
        return -1

    return time.time() - start_time

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
compile_processes_args.append((DEFAULT_DECOMPILER_DL, DEFAULT_DECOMPILER_DL+SOUFFLE_COMPILED_SUFFIX))

if not args.disable_scalable_fallback:
    compile_processes_args.append((FALLBACK_SCALABLE_DECOMPILER_DL, FALLBACK_SCALABLE_DECOMPILER_DL+SOUFFLE_COMPILED_SUFFIX))

if not args.disable_inline:
    compile_processes_args.append((DEFAULT_INLINER_DL, DEFAULT_INLINER_DL+SOUFFLE_COMPILED_SUFFIX))

if not args.disable_precise_fallback:
    compile_processes_args.append((FALLBACK_PRECISE_DECOMPILER_DL, FALLBACK_PRECISE_DECOMPILER_DL+SOUFFLE_COMPILED_SUFFIX))

clients_split = [a.strip() for a in args.client.split(',')]
souffle_clients = [a for a in clients_split if a.endswith('.dl')]
other_clients = [a for a in clients_split if not (a.endswith('.dl') or a == '')]

pre_clients_split = [a.strip() for a in args.pre_client.split(',')]
souffle_pre_clients = [a for a in pre_clients_split if a.endswith('.dl')]
other_pre_clients = [a for a in pre_clients_split if not (a.endswith('.dl') or a == '')]

if not args.interpreted:
    for c in souffle_pre_clients:
        compile_processes_args.append((c, c+SOUFFLE_COMPILED_SUFFIX))

    for c in souffle_clients:
        compile_processes_args.append((c, c+SOUFFLE_COMPILED_SUFFIX))

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

                if not proc.is_alive():
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
            if ':' in k: # tell-tale sign for vulnerability key
                vulnerability_counts[k] += 1
            if isinstance(a, int):
                analytics_sums[k] += a
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

    sys.exit(1)
