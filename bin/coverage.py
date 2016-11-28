from os import listdir
from os.path import abspath, dirname, join
from multiprocessing import Process, Manager
import time
import sys
import itertools

src_path = join(dirname(abspath(__file__)), "../src")
sys.path.insert(0, src_path)

# Local project imports
import exporter
import dataflow
import tac_cfg

def analyse_contract(filename, return_dict):
  try:
    with open(join(d, filename)) as f:
      cfg = tac_cfg.TACGraph.from_bytecode(f, True)
      for _ in range(4):
        dataflow.stack_analysis(cfg)
        cfg.clone_ambiguous_jump_blocks()

      if cfg.has_unresolved_jump:
        return_dict['status'] = "unresolved"
      else:
        return_dict['status'] = "resolved"

  except Exception as e:
    print("Error: {}".format(e))
    return_dict['status'] = "error"



if __name__ == "__main__":
  d = '../../contract_dump/contracts'
  start = 0
  stop = 10000

  runtime_files = filter(lambda f: f.endswith("runtime.hex"), listdir(d))

  sliced = itertools.islice(runtime_files, start, stop)

  timeout = 1

  total_num = 0
  resolved_num = 0
  unresolved_num = 0
  timeout_num = 0
  error_num = 0

  resolved_names = []
  unresolved_names = []
  timeout_names = []
  error_names = []

  manager = Manager()
  return_dict = manager.dict()

  for i, filename in enumerate(sliced):
    print("{}: {}.".format(i, filename))
    total_num += 1
    proc = Process(target=analyse_contract, args=(filename, return_dict))

    start_time = time.time()
    proc.start()

    while time.time() - start_time < timeout:
      if proc.is_alive():
        time.sleep(0.01)
      else:
        proc.join()

        if return_dict['status'] == "unresolved":
          unresolved_num += 1
          unresolved_names.append(filename)
          print("Unresolved.")
        elif return_dict['status'] == "error":
          error_num += 1
          error_names.append(filename)
        else:
          resolved_num += 1
          resolved_names.append(filename)

        break
    else:
      proc.terminate()
      timeout_num += 1
      timeout_names.append(filename)
      print("Timed out.")

  print("Resolved: {}/{}".format(resolved_num, total_num))
  print("Unresolved: {}/{}".format(unresolved_num, total_num))
  print("Timed Out: {}/{}".format(timeout_num, total_num))
  print("Errors: {}/{}".format(error_num, total_num))

  with open("results/resolved.txt", 'w') as f:
    f.write("\n".join(resolved_names))
  with open("results/unresolved.txt", 'w') as f:
    f.write("\n".join(unresolved_names))
  with open("results/timeout.txt", 'w') as f:
    f.write("\n".join(timeout_names))
  with open("results/error.txt", 'w') as f:
    f.writelines("\n".join(error_names))
