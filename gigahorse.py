#!/usr/bin/env python3

## IMPORTS

import argparse
import json
import logging
import shutil
import sys
import time
from collections import defaultdict
from multiprocessing import Process, SimpleQueue, Manager, Event, cpu_count
from typing import List, Tuple, Any, Dict, DefaultDict
from os.path import join, getsize
import os

# Local project imports
from src.common import GIGAHORSE_DIR, DEFAULT_SOUFFLE_BIN, log
from src.runners import get_souffle_executable_path, compile_datalog, AbstractFactGenerator, DecompilerFactGenerator, CustomFactGenerator, MixedFactGenerator, AnalysisExecutor, TimeoutException

## Constants

DEFAULT_TAC_GEN_CONFIG_FILE = join(GIGAHORSE_DIR, 'tac_gen_config.json')

DEFAULT_RESULTS_FILE = 'results.json'
"""File to write results to by default."""

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
                    help="Forcibly halt decompilation/analysis of a single contact after "
                         "the specified number of seconds. Separate timers for decompilation and anaysis.")

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

parser.add_argument("-q",
                    "--quiet",
                    nargs="?",
                    default=False,
                    help="Silence output.")

parser.add_argument("--rerun_clients",
                    action="store_true",
                    default=False,
                    help="Rerun client analyses. Only attempts to decompile if it hasn't tried in the current working dir.")

parser.add_argument("--restart",
                    action="store_true",
                    default=False,
                    help="Erase working dir and decompile/analyze from scratch.")

parser.add_argument("--debug",
                    action="store_true",
                    default=False,
                    help="Various minor changes to aid development. Halts on souffle compilation failure.")

parser.add_argument("--reuse_datalog_bin",
                    action="store_true",
                    default=False,
                    help="Do not recompile the datalog binaries.")

parser.add_argument("-i",
                    "--interpreted",
                    action="store_true",
                    default=False,
                    help="Run souffle in interpreted mode.")

parser.add_argument(
    "--tac_gen_config",
    nargs="?",
    default=DEFAULT_TAC_GEN_CONFIG_FILE,
    metavar="TAC_GEN_CONFIG",
    help="the location of the TAC generation configuration file",
)

def get_working_dir(contract_name: str) -> str:
    return join(os.path.abspath(args.working_dir), os.path.split(contract_name)[1].split('.')[0])

def prepare_working_dir(contract_name: str) -> Tuple[bool, str, str]:
    newdir = get_working_dir(contract_name)
    out_dir = join(newdir, 'out')

    if os.path.isdir(newdir):
        return True, newdir, out_dir

    # recreate dir
    os.makedirs(newdir)
    os.makedirs(out_dir)
    return False, newdir, out_dir

def get_souffle_macros() -> str:
    souffle_macros = f'GIGAHORSE_DIR={GIGAHORSE_DIR} {args.souffle_macros}'.strip()

    if not args.debug:
        souffle_macros += ' BULK_ANALYSIS='

    if args.enable_limitsize:
        souffle_macros += ' ENABLE_LIMITSIZE='

    if args.early_cloning:
        souffle_macros += ' BLOCK_CLONING=HeuristicBlockCloner'

    return souffle_macros

def analyze_contract(index: int, contract_filename: str, result_queue, fact_generator: AbstractFactGenerator, souffle_clients: List[str], other_clients: List[str]) -> None:
    """
    Perform static analysis on a contract, storing the result in the queue.
    This is a worker function to be passed to a subprocess.

    Args:
        index: the number of the particular contract being analyzed
        contract_filename: the absolute path of the contract bytecode file to process
        result_queue: a multiprocessing queue in which to store the analysis results
        fact_generator: the fact generator to be used (decompiler is used by default)
        souffle_clients: list of souffle datalog clients
        other_clients: list of other clients (language agnostic)
    """
    analysis_executor = fact_generator.analysis_executor
    try:
        # prepare working directory
        exists, work_dir, out_dir = prepare_working_dir(contract_filename)
        assert not(args.restart and exists)
        analytics: Dict[str, Any] = {}
        contract_name = os.path.split(contract_filename)[1]
        with open(contract_filename) as file:
            bytecode = file.read().strip()

        if exists:
            disassemble_time = 0.0
            decomp_time = 0.0
            inline_time = 0.0
            decompiler_config = None
        else:
            start_time = time.time()
            disassemble_time, decomp_time, decompiler_config = fact_generator.generate_facts(contract_filename, work_dir, out_dir)

            inline_start = time.time()
            if not args.disable_inline:
                # ignore timeouts and errors here
                analysis_executor.run_clients([DEFAULT_INLINER_DL]*DEFAULT_INLINER_ROUNDS, [], out_dir, out_dir, start_time)

            inline_time = time.time() - inline_start

            # end decompilation
        if exists and not args.rerun_clients:
            return

        # Do not attempt to decompile for earlier timeouts when using --rerun_clients
        if args.rerun_clients and not fact_generator.decomp_out_produced(out_dir):
            raise TimeoutException()

        client_start = time.time()
        timeouts, errors = analysis_executor.run_clients(souffle_clients, other_clients, out_dir, out_dir, client_start)

        # Collect the results and put them in the result queue
        files = []
        for fname in os.listdir(out_dir):
            fpath = join(out_dir, fname)
            if getsize(fpath) != 0:
                files.append(fname.split(".")[0])
        meta = []
        # Decompile + Analysis time
        analytics['disassemble_time'] = disassemble_time
        analytics['decomp_time'] = decomp_time
        analytics['inline_time'] = inline_time
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


def get_gigahorse_analytics(out_dir: str, analytics: dict) -> None:
    for fname in os.listdir(out_dir):
        fpath = join(out_dir, fname)
        if not (fname.startswith('Analytics_') or fname.startswith('Metric_')):
            continue
        stat_name = fname.split(".")[0]
        analytics[stat_name] = sum(1 for line in open(join(out_dir, fname)))

    for fname in os.listdir(out_dir):
        fpath = join(out_dir, fname)
        if not fname.startswith('Verbatim_'):
            continue
        stat_name = fname.split(".")[0]
        analytics[stat_name] = open(join(out_dir, fname)).read()

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

def flush_queue(run_sig: Any, result_queue: SimpleQueue, result_list: Any) -> None:
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

def write_results(res_list: Any, results_file: str) -> None:
    """
    Filters the results in res_list, logging the appropriate messages
    and writting them to the results_file json file
    """
    total = len(res_list)
    vulnerability_counts: DefaultDict[str, int] = defaultdict(int)
    analytics_sums: DefaultDict[str, int] = defaultdict(int)
    meta_counts: DefaultDict[str, int] = defaultdict(int)
    all_files = set()
    for _, files, meta, analytics in res_list:
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

    log("\nWriting results to {}".format(results_file))
    with open(results_file, 'w') as f:
        f.write(json.dumps(list(res_list), indent=1))

def batch_analysis(fact_generator: AbstractFactGenerator, souffle_clients: List[str], other_clients: List[str], contracts: List[str], num_of_jobs: int) -> Any:
    """
    Given a fact generator and the client lists, analyzes the contracts list, using num_of_jobs parallel jobs/processes
    """
    # Set up multiprocessing result list and queue.
    manager = Manager()

    # This list contains analysis results as
    # (filename, category, meta, analytics) quadruples.
    res_list: Any = manager.list()

    # Holds results transiently before flushing to res_list
    res_queue: SimpleQueue = SimpleQueue()

    # Start the periodic flush process, only run while run_signal is set.
    run_signal = Event()
    run_signal.set()
    flush_proc = Process(target=flush_queue, args=(run_signal, res_queue, res_list))
    flush_proc.start()

    workers: List[Dict[str, Any]] = []
    avail_jobs = list(range(num_of_jobs))
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
                    proc = Process(target=analyze_contract, args=(index, contract_name, res_queue, fact_generator, souffle_clients, other_clients))
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

        log(f"\nFinished {len(res_list)} contracts...\n")
        return res_list

    except Exception as e:
        import traceback

        traceback.print_exc()
        flush_proc.terminate()

        sys.exit(1)


def run_gigahorse(args, fact_generator: AbstractFactGenerator) -> None:
    """
    Run gigahorse, passing the cmd line args and fact generator type as arguments
    """
    log_level = logging.WARNING if args.quiet else logging.INFO + 1
    logging.basicConfig(format='%(message)s', level=log_level)

    analysis_executor = AnalysisExecutor(args.timeout_secs, args.interpreted, args.minimum_client_time, args.debug, args.souffle_bin, args.cache_dir, get_souffle_macros())

    fact_generator.analysis_executor = analysis_executor

    clients_split = [a.strip() for a in args.client.split(',')]
    souffle_clients = [a for a in clients_split if a.endswith('.dl')]
    other_clients = [a for a in clients_split if not (a.endswith('.dl') or a == '')]


    if not args.interpreted:
        # Here we compile the decompiler and any of its clients in parallel :)
        souffle_files = fact_generator.get_datalog_files()

        if not args.disable_inline:
            souffle_files.append(DEFAULT_INLINER_DL)

        souffle_files += souffle_clients

        running_processes = []
        for file in souffle_files:
            proc = Process(target = compile_datalog, args=(file, args.souffle_bin, args.cache_dir, args.reuse_datalog_bin, get_souffle_macros()))
            proc.start()
            running_processes.append(proc)

    if args.restart:
        log("Removing working directory {}".format(args.working_dir))
        shutil.rmtree(args.working_dir, ignore_errors = True)

    if not args.interpreted:
        for p in running_processes:
            p.join()
            if args.debug and p.exitcode:
                raise Exception("Souffle binary compilation failed, stopping.")

        # check all programs have been compiled
        for file in souffle_files:
            open(get_souffle_executable_path(args.cache_dir, file), 'r') # check program exists

    # Extract contract filenames.
    log("Processing contract names...")

    contracts = []

    for filepath in args.filepath:
        if os.path.isdir(filepath):
            if args.interpreted:
                log("[WARNING]: Running batch analysis in interpreted mode.")
            unfiltered = [join(filepath, f) for f in os.listdir(filepath)]
        else:
            unfiltered = [filepath]

        contracts += [u for u in unfiltered if fact_generator.match_pattern(u)]

    contracts = contracts[args.skip:]

    log(f"Discovered {len(contracts)} contracts. Setting up workers.")
    res_list= batch_analysis(fact_generator, souffle_clients, other_clients, contracts, args.jobs)
    write_results(res_list, args.results_file)

if __name__ == "__main__":
    # Decompiler tuning
    parser.add_argument("-cd",
                        "--context_depth",
                        type=int,
                        nargs="?",
                        metavar="NUM",
                        help="Override the maximum context depth for decompilation (default is 20).")

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

    args = parser.parse_args()

    tac_gen_config_json = args.tac_gen_config
    with open(tac_gen_config_json, 'r') as config:
        tac_gen_config = json.loads(config.read())
        if len(tac_gen_config["handlers"]) == 0: #if no handlers defined, default to classic decompilation
            run_gigahorse(args, DecompilerFactGenerator(args, ".*.hex"))
        elif len(tac_gen_config["handlers"]) == 1: # if one handler defined, can be either classic decompilation, or custom script
            tac_gen = tac_gen_config["handlers"][0]
            if tac_gen["tacGenScripts"]["defaultDecomp"] == "true":
                run_gigahorse(args, DecompilerFactGenerator(args, tac_gen["fileRegex"]))
            else:
                run_gigahorse(args, CustomFactGenerator(tac_gen["fileRegex"], tac_gen["tacGenScripts"]["customScripts"]))
        elif len(tac_gen_config["handlers"]) > 1: # if multiple handlers have been defined, they will be selected based on the file regex
            fact_generator = MixedFactGenerator(args)
            for tac_gen in tac_gen_config["handlers"]:
                pattern = tac_gen["fileRegex"]
                scripts = tac_gen["tacGenScripts"]["customScripts"]
                is_default = tac_gen["tacGenScripts"]["defaultDecomp"] == "true"
                fact_generator.add_fact_generator(pattern, scripts, is_default, args)
            run_gigahorse(args, fact_generator)
