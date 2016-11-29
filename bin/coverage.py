#!/usr/bin/env python3

from os import listdir, makedirs
from os.path import abspath, dirname, join
from multiprocessing import Process, SimpleQueue, Manager, Event
import time
import sys
import itertools

src_path = join(dirname(abspath(__file__)), "../src")
sys.path.insert(0, src_path)

# Local project imports
import dataflow
import tac_cfg
import logger

ll = logger.log_low

unresolved = 0
resolved = 1
timeout = 3
error = 4

def analyse_contract(filename, result_queue):
  try:
    with open(join(contract_dir, filename)) as f:
      cfg = tac_cfg.TACGraph.from_bytecode(f)
      for _ in range(4):
        dataflow.stack_analysis(cfg)
        cfg.clone_ambiguous_jump_blocks()

      if cfg.has_unresolved_jump:
        result_queue.put((filename, unresolved))
        ll("Unresolved.")
      else:
        result_queue.put((filename, resolved))

  except Exception as e:
    ll("Error: {}".format(e))
    result_queue.put((filename, error))

def flush_queue(period, run_signal, result_queue, result_dict):
  while run_signal.is_set():
    time.sleep(period)
    while not result_queue.empty():
      item = result_queue.get()
      result_dict[item[1]] = result_dict[item[1]] + [item[0]]

if __name__ == "__main__":
  if "-q" in sys.argv:
    logger.LOG_LEVEL = logger.Verbosity.SILENT
  else:
    logger.LOG_LEVEL = logger.Verbosity.MEDIUM


  contract_dir = '../../contract_dump/contracts'
  start = 0
  stop = 10000

  runtime_files = filter(lambda f: f.endswith("runtime.hex"),
                         listdir(contract_dir))

  with open("10kresults/timeout.txt", 'r') as f:
    runtime_files = [l.strip() for l in f.readlines()]

  sliced = itertools.islice(runtime_files, start, stop)
  #sliced = runtime_files

  timeout_secs = 50
  flush_period = 3

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
    for i, filename in enumerate(sliced):
      ll("{}: {}.".format(i, filename))
      proc = Process(target=analyse_contract, args=(filename, res_queue))

      start_time = time.time()
      proc.start()

      while time.time() - start_time < timeout_secs:
        if proc.is_alive():
          time.sleep(0.01)
        else:
          proc.join()
          break
      else:
        res_queue.put((filename, timeout))
        proc.terminate()
        ll("Timed out.")

    ll("\nFinishing...\n")
    run_signal.clear()
    flush_proc.join(flush_period + 1)

    outdir = "results/"
    makedirs(outdir, exist_ok=True)

    r = res_dict[resolved]
    u = res_dict[unresolved]
    t = res_dict[timeout]
    e = res_dict[error]
    total = sum(len(l) for l in res_dict.values())

    with open(outdir + "resolved.txt", 'w') as f:
      f.write("\n".join(r) + "\n")
    with open(outdir + "unresolved.txt", 'w') as f:
      f.write("\n".join(u) + "\n")
    with open(outdir + "timeout.txt", 'w') as f:
      f.write("\n".join(t) + "\n")
    with open(outdir + "error.txt", 'w') as f:
      f.writelines("\n".join(e) + "\n")

    ll("Resolved: {}/{}".format(len(r), total))
    ll("Unresolved: {}/{}".format(len(u), total))
    ll("Timed Out: {}/{}".format(len(t), total))
    ll("Errors: {}/{}".format(len(e), total))
  except Exception as e:
    import traceback
    traceback.print_exc()
    flush_proc.terminate()
