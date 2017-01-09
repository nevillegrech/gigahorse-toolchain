#!/usr/bin/env python3

from os import listdir, makedirs
from os.path import abspath, dirname, join
from multiprocessing import Process, SimpleQueue, Manager, Event
import time
import sys
import itertools

# Add the source directory to the path to ensure the imports work
src_path = join(dirname(abspath(__file__)), "../../src")
sys.path.insert(0, src_path)

# Local project imports
import dataflow
import tac_cfg
import logger
ll = logger.log_low

### Constants ###
unresolved = 0
resolved = 1
timeout = 3
error = 4

# The location to grab contracts from (as bytecode files)
contract_dir = '../../../contract_dump/contracts'
# The location to write the results
results_dir = "non_error_results/"

# grab filenames from a specified file instead of a directory listing
from_file = True
filenames_file = "results/error.txt"

# If not process all, then a quantity of contracts specified by the indices
process_all = True
start_index = 0
stop_index = 100

# Kill the analysis after this many seconds
timeout_secs = 120

# Wait a little to flush the files and join the processes when concluding
flush_period = 3

# The number of times to run the analysis loop.
analysis_iterations = 3


def analyse_contract(filename, result_queue):
  """Perform dataflow analysis on a contract, storing the result in the queue."""
  try:
    with open(join(contract_dir, filename)) as file:
      cfg = tac_cfg.TACGraph.from_bytecode(file, strict=False)

      for _ in range(analysis_iterations):
        dataflow.stack_analysis(cfg)
        cfg.clone_ambiguous_jump_blocks()
      cfg.hook_up_def_site_jumps()
      dataflow.stack_analysis(cfg, generate_throws=True)

      cfg.remove_unreachable_code()
      cfg.merge_duplicate_blocks(ignore_preds=True, ignore_succs=True)
      cfg.hook_up_def_site_jumps()

      if cfg.has_unresolved_jump:
        result_queue.put((filename, unresolved))
        ll("Unresolved.")
      else:
        result_queue.put((filename, resolved))

  except Exception as e:
    ll("Error: {}".format(e))
    result_queue.put((filename, error))


def flush_queue(period, run_signal, result_queue, result_dict):
  """For flushing the queue periodically to a dict so it doesn't fill up."""
  while run_signal.is_set():
    time.sleep(period)
    while not result_queue.empty():
      item = result_queue.get()
      result_dict[item[1]] = result_dict[item[1]] + [item[0]]
      # NB: += doesn't work here

if __name__ == "__main__":
  if "-q" in sys.argv:
    logger.LOG_LEVEL = logger.Verbosity.SILENT
  else:
    logger.LOG_LEVEL = logger.Verbosity.MEDIUM

  # Extract contract filenames.
  runtime_files = filter(lambda filename: filename.endswith("runtime.hex"),
                         listdir(contract_dir))
  if from_file:
    with open(filenames_file, 'r') as f:
      runtime_files = [l.strip() for l in f.readlines()]

  sliced = itertools.islice(runtime_files, start_index, stop_index)
  if process_all:
    sliced = runtime_files

  # Set up multiprocessing stuff.
  manager = Manager()
  res_dict = manager.dict()
  res_queue = SimpleQueue()

  res_dict[resolved] = []
  res_dict[unresolved] = []
  res_dict[timeout] = []
  res_dict[error] = []

  run_signal = Event()
  run_signal.set()
  flush_proc = Process(target=flush_queue, args=(flush_period, run_signal,
                                                 res_queue, res_dict))
  flush_proc.start()

  try:
    # Process each contract in turn, timing out if it takes too long.
    for i, fname in enumerate(sliced):
      ll("{}: {}.".format(i, fname))
      proc = Process(target=analyse_contract, args=(fname, res_queue))

      start_time = time.time()
      proc.start()

      while time.time() - start_time < timeout_secs:
        if proc.is_alive():
          time.sleep(0.01)
        else:
          proc.join()
          break
      else:
        res_queue.put((fname, timeout))
        proc.terminate()
        ll("Timed out.")

    # Conclude and write results to file.
    ll("\nFinishing...\n")
    run_signal.clear()
    flush_proc.join(flush_period + 1)

    makedirs(results_dir, exist_ok=True)

    r = res_dict[resolved]
    u = res_dict[unresolved]
    t = res_dict[timeout]
    e = res_dict[error]
    total = sum(len(l) for l in res_dict.values())

    with open(results_dir + "resolved.txt", 'w') as f:
      f.write("\n".join(r) + "\n")
    with open(results_dir + "unresolved.txt", 'w') as f:
      f.write("\n".join(u) + "\n")
    with open(results_dir + "timeout.txt", 'w') as f:
      f.write("\n".join(t) + "\n")
    with open(results_dir + "error.txt", 'w') as f:
      f.writelines("\n".join(e) + "\n")

    ll("Resolved: {}/{}".format(len(r), total))
    ll("Unresolved: {}/{}".format(len(u), total))
    ll("Timed Out: {}/{}".format(len(t), total))
    ll("Errors: {}/{}".format(len(e), total))
  except Exception as e:
    import traceback
    traceback.print_exc()
    flush_proc.terminate()
